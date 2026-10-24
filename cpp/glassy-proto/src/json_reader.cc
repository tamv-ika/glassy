#include "json_reader.h"

namespace glassy::proto {
namespace {

bool is_digit(char c) { return c >= '0' && c <= '9'; }

int hex_value(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

bool is_high_surrogate(uint32_t u) { return u >= 0xd800 && u <= 0xdbff; }
bool is_low_surrogate(uint32_t u) { return u >= 0xdc00 && u <= 0xdfff; }

}  // namespace

JsonToken JsonReader::fail() {
  state_ = State::kError;
  return JsonToken::kError;
}

void JsonReader::skip_whitespace() {
  // RFC 8259 §2: the only insignificant whitespace.
  while (pos_ < doc_.size()) {
    const char c = doc_[pos_];
    if (c != ' ' && c != '\t' && c != '\n' && c != '\r') return;
    ++pos_;
  }
}

void JsonReader::after_value() { state_ = depth_ == 0 ? State::kDone : State::kCommaOrEnd; }

JsonToken JsonReader::close_container() {
  const JsonToken t = top_is_object() ? JsonToken::kObjectEnd : JsonToken::kArrayEnd;
  ++pos_;
  --depth_;
  after_value();
  return t;
}

JsonToken JsonReader::next() {
  for (;;) {
    if (state_ == State::kError) return JsonToken::kError;
    skip_whitespace();
    const bool at_end = pos_ == doc_.size();
    const char c = at_end ? '\0' : doc_[pos_];
    switch (state_) {
      case State::kDone:
        return at_end ? JsonToken::kEnd : fail();
      case State::kKeyOrEnd:
        if (c == '}') return close_container();
        [[fallthrough]];
      case State::kKey:
        if (c != '"' || !lex_string()) return fail();
        skip_whitespace();
        if (pos_ == doc_.size() || doc_[pos_] != ':') return fail();
        ++pos_;
        state_ = State::kValue;
        return JsonToken::kKey;
      case State::kCommaOrEnd:
        if (c == ',') {
          // No closer may follow a comma: trailing commas are not JSON.
          ++pos_;
          state_ = top_is_object() ? State::kKey : State::kValue;
          continue;
        }
        if (!at_end && c == (top_is_object() ? '}' : ']')) return close_container();
        return fail();
      case State::kValueOrEnd:
        if (c == ']') return close_container();
        [[fallthrough]];
      case State::kStart:
      case State::kValue:
        return at_end ? fail() : lex_value();
      case State::kError:
        return JsonToken::kError;
    }
  }
}

JsonToken JsonReader::lex_value() {
  const char c = doc_[pos_];
  if (c == '{' || c == '[') {
    if (depth_ == kMaxDepth) return fail();
    is_object_[depth_++] = c == '{';
    ++pos_;
    state_ = c == '{' ? State::kKeyOrEnd : State::kValueOrEnd;
    return c == '{' ? JsonToken::kObjectBegin : JsonToken::kArrayBegin;
  }
  JsonToken t;
  bool ok;
  if (c == '"') {
    t = JsonToken::kString;
    ok = lex_string();
  } else if (c == '-' || is_digit(c)) {
    t = JsonToken::kNumber;
    ok = lex_number();
  } else if (c == 't') {
    t = JsonToken::kTrue;
    ok = lex_literal("true");
  } else if (c == 'f') {
    t = JsonToken::kFalse;
    ok = lex_literal("false");
  } else if (c == 'n') {
    t = JsonToken::kNull;
    ok = lex_literal("null");
  } else {
    return fail();
  }
  if (!ok) return fail();
  // Whatever follows (e.g. `1x`, `truex`) is judged by the next state.
  after_value();
  return t;
}

bool JsonReader::lex_string() {
  ++pos_;  // opening quote
  const size_t start = pos_;
  escaped_ = false;
  strict_utf16_ = true;
  bool pending_high = false;  // a \uD800-\uDBFF escape still waiting for its low half
  while (pos_ < doc_.size()) {
    const char c = doc_[pos_];
    if (c == '"') {
      if (pending_high) strict_utf16_ = false;
      text_ = doc_.substr(start, pos_ - start);
      ++pos_;
      return true;
    }
    // RFC 8259 §7: control characters must be escaped.
    if (static_cast<unsigned char>(c) < 0x20) return false;
    if (c != '\\') {
      if (pending_high) strict_utf16_ = false;
      pending_high = false;
      ++pos_;
      continue;
    }
    escaped_ = true;
    if (doc_.size() - pos_ < 2) return false;
    const char e = doc_[pos_ + 1];
    pos_ += 2;
    if (e == '"' || e == '\\' || e == '/' || e == 'b' || e == 'f' || e == 'n' || e == 'r' ||
        e == 't') {
      if (pending_high) strict_utf16_ = false;
      pending_high = false;
      continue;
    }
    if (e != 'u' || doc_.size() - pos_ < 4) return false;
    uint32_t u = 0;
    for (size_t k = 0; k < 4; ++k) {
      const int h = hex_value(doc_[pos_ + k]);
      if (h < 0) return false;
      u = (u << 4) | static_cast<uint32_t>(h);
    }
    pos_ += 4;
    if (pending_high) {
      if (!is_low_surrogate(u)) strict_utf16_ = false;
      pending_high = false;
    } else if (is_high_surrogate(u)) {
      pending_high = true;
    } else if (is_low_surrogate(u)) {
      strict_utf16_ = false;
    }
  }
  return false;  // unterminated
}

bool JsonReader::lex_number() {
  // RFC 8259 §6: -?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?; magnitude is not limited.
  const size_t start = pos_;
  auto digits = [&] {
    const size_t from = pos_;
    while (pos_ < doc_.size() && is_digit(doc_[pos_])) ++pos_;
    return pos_ > from;
  };
  if (doc_[pos_] == '-') ++pos_;
  if (pos_ == doc_.size()) return false;
  if (doc_[pos_] == '0') {
    ++pos_;
    if (pos_ < doc_.size() && is_digit(doc_[pos_])) return false;  // leading zero
  } else if (!digits()) {
    return false;
  }
  if (pos_ < doc_.size() && doc_[pos_] == '.') {
    ++pos_;
    if (!digits()) return false;
  }
  if (pos_ < doc_.size() && (doc_[pos_] == 'e' || doc_[pos_] == 'E')) {
    ++pos_;
    if (pos_ < doc_.size() && (doc_[pos_] == '+' || doc_[pos_] == '-')) ++pos_;
    if (!digits()) return false;
  }
  text_ = doc_.substr(start, pos_ - start);
  return true;
}

bool JsonReader::lex_literal(std::string_view word) {
  if (doc_.substr(pos_, word.size()) != word) return false;
  pos_ += word.size();
  return true;
}

bool JsonReader::skip_value(JsonToken first) {
  if (first == JsonToken::kError) return false;
  if (first != JsonToken::kObjectBegin && first != JsonToken::kArrayBegin) return true;
  const size_t target = depth_ - 1;
  while (depth_ > target) {
    if (next() == JsonToken::kError) return false;
  }
  return true;
}

}  // namespace glassy::proto

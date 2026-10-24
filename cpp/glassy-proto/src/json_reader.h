#ifndef GLASSY_PROTO_JSON_READER_H_
#define GLASSY_PROTO_JSON_READER_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace glassy::proto {

enum class JsonToken : uint8_t {
  kObjectBegin,
  kObjectEnd,
  kArrayBegin,
  kArrayEnd,
  kKey,
  kString,
  kNumber,
  kTrue,
  kFalse,
  kNull,
  kEnd,    // the document ended after one value and trailing whitespace
  kError,  // RFC 8259 violation or nesting deeper than kMaxDepth; sticky
};

// Single-pass, allocation-free pull tokenizer for one RFC 8259 JSON text. It enforces the full
// grammar (no trailing commas or garbage, no leading zeros, valid escapes, no raw control
// characters in strings) with a fixed-size container stack. Strings are not unescaped: callers
// get the raw bytes between the quotes plus flags. The input must already be valid UTF-8.
class JsonReader {
 public:
  static constexpr size_t kMaxDepth = 8;

  explicit JsonReader(std::string_view doc) : doc_(doc) {}

  JsonToken next();

  // Skips the rest of the value whose first token `first` was just returned by next(); a no-op
  // for scalars. Returns false on a grammar error (including `first` == kError).
  bool skip_value(JsonToken first);

  // For kKey/kString: raw bytes between the quotes. For kNumber: the number token.
  std::string_view text() const { return text_; }
  // kKey/kString contained a backslash escape.
  bool escaped() const { return escaped_; }
  // kKey/kString: every \u escape forms valid UTF-16 (a high surrogate immediately followed by
  // a low one). serde_json accepts lone surrogates only in values it ignores, so callers need
  // this for keys of the objects they interpret.
  bool strict_utf16() const { return strict_utf16_; }

 private:
  enum class State : uint8_t {
    kStart,       // the top-level value
    kValue,       // after ':' or after ',' in an array
    kValueOrEnd,  // after '['
    kKey,         // after ',' in an object
    kKeyOrEnd,    // after '{'
    kCommaOrEnd,  // after a value inside a container
    kDone,        // after the top-level value
    kError,
  };

  JsonToken fail();
  JsonToken lex_value();
  JsonToken close_container();
  void after_value();
  void skip_whitespace();
  bool lex_string();
  bool lex_number();
  bool lex_literal(std::string_view word);
  bool top_is_object() const { return is_object_[depth_ - 1]; }

  std::string_view doc_;
  size_t pos_ = 0;
  State state_ = State::kStart;
  std::array<bool, kMaxDepth> is_object_{};
  size_t depth_ = 0;
  std::string_view text_;
  bool escaped_ = false;
  bool strict_utf16_ = true;
};

}  // namespace glassy::proto

#endif  // GLASSY_PROTO_JSON_READER_H_

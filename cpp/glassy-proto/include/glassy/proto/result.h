#ifndef GLASSY_PROTO_RESULT_H_
#define GLASSY_PROTO_RESULT_H_

#include <utility>
#include <variant>

#include "glassy/proto/error.h"

namespace glassy::proto {

// Exception-free value-or-error. T must be default constructible (all codec outputs are
// small trivially constructible structs), which avoids dynamic allocation.
template <class T>
class Result {
 public:
  Result(T value) : value_(std::move(value)), error_(Error::kOk) {}  // NOLINT: implicit by design
  Result(Error error) : value_(), error_(error) {}                   // NOLINT: implicit by design

  bool ok() const { return error_ == Error::kOk; }
  Error error() const { return error_; }
  // Only meaningful when ok().
  const T& value() const { return value_; }

 private:
  T value_;
  Error error_;
};

using Status = Result<std::monostate>;

}  // namespace glassy::proto

#endif  // GLASSY_PROTO_RESULT_H_

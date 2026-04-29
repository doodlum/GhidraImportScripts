#pragma once
#include <cstddef>
#include <tuple>
namespace binary_io {
class file_istream {
public:
    file_istream() = default;
    template<typename T> file_istream(T&&) {}
    template<typename... Args> std::tuple<Args...> read() { return {}; }
    template<typename... Args> void read(Args&...) {}
    void seek_relative(std::ptrdiff_t) {}
};
class file_ostream {};
}

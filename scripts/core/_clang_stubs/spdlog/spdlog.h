#pragma once
namespace spdlog {
  struct source_loc { const char* filename = nullptr; int line = 0; const char* funcname = nullptr; };
  class logger {};
  namespace level { enum level_enum { trace, debug, info, warn, err, critical, off }; }
  template<typename... Args> void log(level::level_enum, Args&&...) {}
  template<typename... Args> void log(source_loc, level::level_enum, Args&&...) {}
}

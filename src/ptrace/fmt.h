#pragma once

#include "spdlog/fmt/fmt.h"
#include "parameter.h"

template <>
struct fmt::formatter<SAIL::core::Parameter> {
  constexpr auto parse(format_parse_context& ctx) { return ctx.begin(); }

  template <typename FormatContext>
  auto format(const SAIL::core::Parameter& d, FormatContext& ctx) {
    return format_to(ctx.out(), "");
  }
};
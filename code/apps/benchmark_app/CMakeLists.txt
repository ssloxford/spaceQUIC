project(CFE_BENCHMARK_APP C)

include_directories(fsw/mission_inc)
include_directories(fsw/platform_inc)

add_cfe_app(benchmark_app fsw/src/benchmark_app.c)

add_cfe_app_dependency(benchmark_app space_quic)

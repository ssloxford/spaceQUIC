cmake_minimum_required(VERSION 2.6.4)
project(CFS_CI_LAB C)

include_directories(fsw/mission_inc)
include_directories(fsw/platform_inc)

aux_source_directory(fsw/src APP_SRC_FILES)

# Create the app module
add_cfe_app(ci_lab ${APP_SRC_FILES})

target_link_libraries(ci_lab Crypto)
add_cfe_app_dependency(ci_lab space_quic)

get_target_property(OUT ci_lab LINK_LIBRARIES)
message(STATUS ${OUT})

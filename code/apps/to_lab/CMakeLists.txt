cmake_minimum_required(VERSION 2.6.4)
project(CFS_TO_LAB C)

# Include source directory for table use
include_directories(fsw/src)

include_directories(fsw/mission_inc)
include_directories(fsw/platform_inc)
include_directories(${ci_lab_MISSION_DIR}/fsw/platform_inc)
include_directories(${sample_app_MISSION_DIR}/fsw/platform_inc)

aux_source_directory(fsw/src APP_SRC_FILES)

# Create the app module
add_cfe_app(to_lab ${APP_SRC_FILES})

target_link_libraries(to_lab Crypto)
add_cfe_app_dependency(to_lab space_quic)

add_cfe_tables(TO_LAB_Subs fsw/tables/to_lab_sub.c)


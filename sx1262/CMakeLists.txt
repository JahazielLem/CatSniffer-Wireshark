# CMakeLists.txt
#
# SPDX-FileCopyrightText: © 2025 Kevin Leon
# SPDX-License-Identifier: GPL-2.0-or-later

include(WiresharkPlugin)

# Plugin name and version info (major minor micro extra)
set_module_info(catsnifferlora 0 0 1 0)

set(DISSECTOR_SRC
	catsnifferlora.c
)

set(PLUGIN_FILES
	plugin.c
	${DISSECTOR_SRC}
)

set_source_files_properties(
	${PLUGIN_FILES}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

register_plugin_files(plugin.c
	plugin
	${DISSECTOR_SRC}
)

add_wireshark_plugin_library(catsnifferlora epan)

target_link_libraries(catsnifferlora epan)

install_plugin(catsnifferlora epan)

file(GLOB DISSECTOR_HEADERS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "*.h")
CHECKAPI(
	NAME
				catsnifferlora
	SWITCHES
			--group dissectors-prohibited
			--group dissectors-restricted
	SOURCES
			${DISSECTOR_SRC}
			${DISSECTOR_HEADERS}
)

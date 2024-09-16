
if(NOT OpenSSL_FOUND)
	message(STATUS "OpenSSL")

	link_directories(/usr/local/lib)
	include_directories(/usr/local/include/)
endif()

list(APPEND DEPS_LIBS crypto)
add_executable(il_tests il_tests.cpp)
target_link_libraries(il_tests PRIVATE binaryninjaapi Catch2::Catch2)

include(CTest)
include(Catch)
catch_discover_tests(il_tests)

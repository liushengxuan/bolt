add_executable(
  bolt_dwio_parquet_decryption_test
  AesDecryptorTest.cpp
  ParquetFileDecryptorTest.cpp)

add_test(
  NAME bolt_dwio_parquet_decryption_test
  COMMAND bolt_dwio_parquet_decryption_test
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(
  bolt_dwio_parquet_decryption_test
  bolt_dwio_parquet_decryption
  bolt_dwio_parquet_arrow_lib
  bolt_memory
  GTest::gtest
  GTest::gtest_main)

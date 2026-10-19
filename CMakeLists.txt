cmake_minimum_required(VERSION 3.30)
project(CryptoGuard VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    # Не больше трёх ошибок за раз
    add_compile_options(-fmax-errors=3)
endif()

# Ищем необходимые библиотеки
find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED COMPONENTS program_options)
find_package(GTest REQUIRED)

# Рекурсивно ищем все используемые .cpp и .h файлы, кроме main.cpp
file(GLOB SRC_FILES "${CMAKE_SOURCE_DIR}/src/*.cpp")
file(GLOB HEADER_FILES "${CMAKE_SOURCE_DIR}/include/*.h")
list(REMOVE_ITEM SRC_FILES "${CMAKE_SOURCE_DIR}/src/main.cpp")

# Создаём статическую библиотеку
add_library(${PROJECT_NAME}_imp STATIC ${SRC_FILES} ${HEADER_FILES})

# Добавляем в проект используемые сторонние библиотеки
target_include_directories(${PROJECT_NAME}_imp PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIR}
    ${Boost_INCLUDE_DIRS}
)
target_link_libraries(${PROJECT_NAME}_imp PRIVATE ${OPENSSL_LIBRARIES} ${Boost_LIBRARIES})

# Создаём исполняемый таргет и линкуем к нему статическую библиотеку
add_executable(${PROJECT_NAME} "${CMAKE_SOURCE_DIR}/src/main.cpp")
target_link_libraries(${PROJECT_NAME} PRIVATE ${PROJECT_NAME}_imp)

#
# Тесты
#

# Рекурсивно ищем все используемые в тестах .cpp файлы
file(GLOB TEST_SRC_FILES "${CMAKE_SOURCE_DIR}/tests/*.cpp")

add_executable(unit_tests "${TEST_SRC_FILES}")
target_include_directories(unit_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(unit_tests
    PRIVATE
        ${PROJECT_NAME}_imp
        GTest::GTest
        GTest::Main)

# Включаем тестирование
enable_testing()
add_test(NAME Tests COMMAND unit_tests)

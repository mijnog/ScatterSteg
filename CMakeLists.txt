cmake_minimum_required(VERSION 3.20)
project(ScatterSteg C)

set(CMAKE_C_STANDARD 17)

add_executable(ScatterSteg main.c
        png_io.h
        png_io.c
        png_io.c)

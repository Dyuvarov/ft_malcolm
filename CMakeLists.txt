cmake_minimum_required(VERSION 3.26)
project(ft_malcolm C)

set(CMAKE_C_STANDARD 99)

include_directories(includes libft)
file(GLOB libft_src
        "libft/*.h"
        "libft/*.c"
)

add_executable(ft_malcolm src/main.c
        includes/ft_status.h ${libft_src}
        includes/malcolm_validator.h
        src/malcolm_validator.c)

#include <stdio.h>
#include <unistd.h>
#include "ft_status.h"
#include "malcolm_validator.h"






int main(int argc, char** argv)
{
    int validation_result = validate_args(argc, argv);
    if (validation_result != SUCCESS) {
        return validation_result;
    }

    char* ip_source = argv[1];
    char* ip_target = argv[3];
    char* mac_source = argv[2];
    char* mac_target = argv[4];

    return SUCCESS;
}

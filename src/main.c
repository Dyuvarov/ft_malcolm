#include <stdio.h>
#include "ft_status.h"
#include "malcolm_validator.h"






int main(int argc, char** argv)
{
    int validation_result = validate_args(argc, argv);
    if (validation_result != SUCCESS) {
        return validation_result;
    }
    return SUCCESS;
}

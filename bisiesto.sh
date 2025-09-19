#!/bin/bash

read -p "¿Cuál fue el año pasado? " year

if (( (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0) )); then
    echo "El año $year es bisiesto ✅"
else
    echo "El año $year NO es bisiesto ❌"
fi

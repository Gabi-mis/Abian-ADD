#!/bin/bash
num=$((RANDOM % 100 + 1))
echo "adivina en 5 intentos un numero aleatorio del 1 al 100"
for i in {1..5}; do
  read -p "intento $i: " x
  [ "$x" -eq "$num" ] && echo "🎉 ¡enhorabuena adivinaste en $i intentos!" && exit
  [ "$x" -lt "$num" ] && echo "el número es MAYOR" || echo "el número es MENOR"
done
echo "❌ Sin intentos. el número era: $num"

#!/bin/bash
for i in {0..127}; do
  input_file="bucket_${i}.csv"
  sort -t ',' -k 1,1 "$input_file" > "temp_sorted.csv"
  mv "temp_sorted.csv" "$input_file"
done

import json
import time
import pandas as pd
import mmh3
import math
import os
from collections import defaultdict

class HyperLogLog:
    def __init__(self, precision=14):
        self.p = precision
        self.m = 2 ** self.p
        self.registers = [0] * self.m

    def _hash(self, value):
        return mmh3.hash(value, signed=False)

    def _get_index_and_rank(self, hashed_value):
        index = hashed_value >> (32 - self.p)
        rank = self._count_leading_zeros((hashed_value << self.p) & 0xFFFFFFFF) + 1
        return index, rank
    
    def _count_leading_zeros(self, value):
        return (32 - len(bin(value)[2:]))
    
    def add(self, value):
        hashed_value = self._hash(value)
        index, rank = self._get_index_and_rank(hashed_value)
        self.registers[index] = max(self.registers[index], rank)
    
    def count(self):
        alpha_m = (0.7213 / (1 + 1.079 / self.m)) * self.m * self.m
        sum_harmonic = sum(2.0 ** (-r) for r in self.registers)
        raw_estimate = alpha_m / sum_harmonic

        if raw_estimate <= 2.5 * self.m:
            zero_registers = self.registers.count(0)
            if zero_registers != 0:
                raw_estimate = self.m * math.log(self.m / zero_registers)
        elif raw_estimate > (1 << 32) / 30.0:
            raw_estimate = -(1 << 32) * math.log(1.0 - raw_estimate / (1 << 32))
        
        return round(raw_estimate)

def load_ip_addresses(file_path):
    unique_ips = set()
    hll = HyperLogLog()
    
    if not os.path.exists(file_path):
        print(f"Помилка: файл '{file_path}' не знайдено! Переконайтеся, що він знаходиться у правильній директорії.")
        print(f"Поточна директорія: {os.getcwd()}")
        print(f"Файли у директорії: {os.listdir('.')}")
        exit(1)
    
    with open(file_path, "r") as file:
        for line in file:
            try:
                log_entry = json.loads(line)
                ip = log_entry.get("remote_addr")
                if ip:
                    unique_ips.add(ip)
                    hll.add(ip)
            except json.JSONDecodeError:
                continue  # Ігноруємо некоректні рядки
    
    return unique_ips, hll

if __name__ == "__main__":
    log_file = "./lms.txt"
    
    start_time = time.time()
    unique_ips, hll = load_ip_addresses(log_file)
    exact_count = len(unique_ips)
    exact_time = time.time() - start_time
    
    start_time = time.time()
    hll_count = hll.count()
    hll_time = time.time() - start_time
    
    # Вивід результатів
    results = pd.DataFrame({
        "Метод": ["Точний підрахунок", "HyperLogLog"],
        "Унікальні IP": [exact_count, hll_count],
        "Час (сек)": [exact_time, hll_time]
    })
    print(results)
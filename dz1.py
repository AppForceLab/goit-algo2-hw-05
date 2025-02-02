import hashlib
import mmh3
import bitarray

class BloomFilter:
    def __init__(self, size: int, num_hashes: int):
        """
        Ініціалізує фільтр Блума з заданим розміром бітового масиву та кількістю хеш-функцій.
        :param size: Розмір бітового масиву
        :param num_hashes: Кількість хеш-функцій
        """
        self.size = size
        self.num_hashes = num_hashes
        self.bit_array = bitarray.bitarray(size)
        self.bit_array.setall(0)

    def _hashes(self, item: str):
        """
        Генерує множину хеш-значень для рядка.
        :param item: Вхідний рядок (пароль)
        :return: Генератор хеш-значень
        """
        for i in range(self.num_hashes):
            yield mmh3.hash(item, i) % self.size

    def add(self, item: str):
        """
        Додає елемент до фільтра Блума.
        :param item: Рядок (пароль)
        """
        for hash_val in self._hashes(item):
            self.bit_array[hash_val] = 1

    def __contains__(self, item: str) -> bool:
        """
        Перевіряє, чи є елемент у фільтрі Блума.
        :param item: Рядок (пароль)
        :return: True, якщо пароль вже, ймовірно, є у фільтрі; False, якщо точно відсутній
        """
        return all(self.bit_array[hash_val] for hash_val in self._hashes(item))

def check_password_uniqueness(bloom_filter: BloomFilter, passwords: list) -> dict:
    """
    Перевіряє список паролів на унікальність за допомогою фільтра Блума.
    :param bloom_filter: Екземпляр фільтра Блума
    :param passwords: Список паролів для перевірки
    :return: Словник {пароль: статус}
    """
    results = {}
    for password in passwords:
        if not isinstance(password, str) or not password:
            results[password] = "Некоректний пароль"
        elif password in bloom_filter:
            results[password] = "вже використаний"
        else:
            results[password] = "унікальний"
            bloom_filter.add(password)
    return results

if __name__ == "__main__":
    # Ініціалізація фільтра Блума
    bloom = BloomFilter(size=1000, num_hashes=3)

    # Додавання існуючих паролів
    existing_passwords = ["password123", "admin123", "qwerty123"]
    for password in existing_passwords:
        bloom.add(password)

    # Перевірка нових паролів
    new_passwords_to_check = ["password123", "newpassword", "admin123", "guest", "", None, 123456]
    results = check_password_uniqueness(bloom, new_passwords_to_check)

    # Виведення результатів
    for password, status in results.items():
        print(f"Пароль '{password}' - {status}.")

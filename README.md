# Async Steam Auth Library

Асинхронная библиотека для авторизации в Steam с поддержкой 2FA и управлением сессиями
Python
aiohttp

🚀 Возможности:

✅ Асинхронная авторизация через логин/пароль

🔒 Поддержка Steam Guard (2FA)

🍪 Сохранение и восстановление сессий через cookies

💰 Получение баланса Steam-кошелька

🔄 Автоматическая обработка редиректов

🛡️ Обход базовой капчи

📦 Установка
Убедитесь, что у вас установлен Python 3.8+

Установите зависимости:

pip install aiohttp rsa yarl

⚙️ Настройка

Создайте файл account.ini в корне проекта:


[Account]

API_KEY = your_steam_api_key

username = your_steam_login

password = your_steam_password

path_secret_maFile = path_to_maFile.json

🛠 Пример использования

Базовая авторизация

from auth_steam import AuthSteam
import asyncio

async def main():
    async with AuthSteam() as auth:
        # Авторизация с логином/паролем
        session = await auth.login()
        
        # Получение баланса
        balance = await auth.get_steam_balance()
        print(f"Баланс: {balance}₽")
        
        # Сохранение сессии
        await auth.save_cookies()

asyncio.run(main())

Использование сохраненной сессии

async def main():
    async with AuthSteam() as auth:
        # Загрузка куков
        await auth.load_cookies()
        
        # Проверка баланса
        balance = await auth.get_steam_balance()
        print(f"Текущий баланс: {balance}₽")


🔧 Методы API
Основные методы
login() - Полная авторизация через Steam

load_cookies() - Загрузка сессии из файла

save_cookies() - Сохранение текущей сессии

get_steam_balance() - Получение баланса кошелька

Расширенные настройки

# Кастомный путь для куков
await auth.save_cookies('./custom_cookies.json')

# Получение "замороженного" баланса
await auth.get_steam_balance(on_hold=True)


🛑 Важно!

🔐 Никогда не коммитьте файлы account.ini и *.json с секретными данными

⚠️ Используйте виртуальное окружение для изоляции зависимостей

🔄 Регулярно обновляйте куки-файлы (раз в 1 дней)

📄 Лицензия
MIT License. Подробнее в файле LICENSE.

Совместимость: Python 3.8+, Windows/Linux/macOS
Поддержка: Сообщить о проблеме
Автор: Ваше имя
Версия: 1.0.0

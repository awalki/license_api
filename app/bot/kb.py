from aiogram import types

kb = [
    [types.KeyboardButton(text="👤 Register"), types.KeyboardButton(text="🔑 License")],
    [types.KeyboardButton(text="👥 Users")],
]

keyboard = types.ReplyKeyboardMarkup(
    keyboard=kb, resize_keyboard=True, input_field_placeholder="Select an option"
)

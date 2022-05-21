import pygame
import tkinter
import tkinter.filedialog

file_types = (("plk", "*.plk"), ("pvk", "*.pvk"), ("sgn", "*.sgn"))


def draw_text(window, rect, text, font):
    text = font.render(text, True, (160, 160, 160))
    text_rect = text.get_rect(center=rect.center)
    window.blit(text, text_rect)


def chosen_file():
    root = tkinter.Tk()
    root.withdraw()
    file_name = tkinter.filedialog.askopenfilename(parent=root)
    root.destroy()
    return file_name


def chosen_key():
    root = tkinter.Tk()
    root.withdraw()
    key = tkinter.filedialog.askopenfilename(parent=root, filetypes=file_types)
    # TODO
    # ze co todo tu niby?
    root.destroy()
    return key

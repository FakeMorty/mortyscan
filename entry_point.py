"""Entry-point для PyInstaller (.exe / standalone бинарник).

PyInstaller не умеет запускать пакеты через -m напрямую, поэтому
этот файл импортирует mortyscan.cli и вызывает main().
"""
from mortyscan.cli import main

if __name__ == "__main__":
    main()

#include "akinator/akinator.h"
#include "libs/logging/logging.h"
#include "tree/dump/dump.h"

#include <locale.h>
#include <stdio.h>
#include <string.h>

const char* DEFAULT_DB_FILE = "akinator1_db.json";

void sw(akinator_t* akin);

int main(void)
{
    setlocale(LC_ALL, "");
    init_logging("log.log", DEBUG);

    CREATE_AKINATOR(akinator1);

    if (akinator_read_file(&akinator1, DEFAULT_DB_FILE, INFO) != OK) { akinator_dtor(&akinator1); close_log_file(); return 1; };
    sw(&akinator1);
    
    akinator_dtor(&akinator1);
    close_log_file();
    return 0;
}

void sw(akinator_t* akin)
{
    int running = 1;
    while (running) 
    {
        say("Что ты хочешь сделать?");
        printf("\n=== Акинатор ===\n");
        printf("1) Прочитать базу\n");
        printf("2) Сохранить базу\n");
        printf("3) Запустить игру\n");
        printf("4) Описать объект\n");
        printf("5) Разница между объектами\n");
        printf("0) Выход\n");
        printf("Ваш выбор: ");
        fflush(stdout);

        int choice = -1;
        if (scanf("%d", &choice) != 1) 
        {
            flush_input();
            continue;
        }
        flush_input();

        switch (choice) 
        {
            case 1: 
            {
                char fname[512] = {  };
                say("Введите имя файла");
                printf("Введите имя файла для чтения (по умолчанию: %s): ", DEFAULT_DB_FILE);
                fflush(stdout);
                read_line(fname, sizeof(fname));
                const char *use_name = fname[0] ? fname : DEFAULT_DB_FILE;

                err_t rc = akinator_read_file(akin, use_name, INFO);
                if (rc != OK)
                {
                    say("Ошибка чтения");
                    printf("Ошибка чтения базы из \"%s\": %d\n", use_name, rc);
                } else
                {
                    say("База прочитана!");   
                    printf("База прочитана из \"%s\".\n", use_name);
                }
                break;
            }
            case 2: 
            {
                char name[512] = {  };
                say("Введите имя файла");
                printf("Введите имя файла для записи (по умолчанию: %s): ", DEFAULT_DB_FILE);
                fflush(stdout);
                read_line(name, sizeof(name));
                const char *use_name = name[0] ? name : DEFAULT_DB_FILE;

                err_t rc = akinator_write_file(akin, use_name);
                if (rc != OK)
                {
                    say("Ошибка записи");
                    printf("Ошибка записи базы в \"%s\": %d\n", use_name, rc);
                } else
                {
                    say("База сохранена!");
                    printf("База сохранена в \"%s\".\n", use_name);
                }
                break;
            }
            case 3: 
            {
                err_t rc = akinator_run(akin);
                if (rc != OK) { say("Ошибка!"); printf("Ошибка во время игры: %d\n", rc); }
                else { say("Игра завершена"); printf("Игра завершена.\n"); }
                break;
            }
            case 4: 
            {
                char name[512] = {  };
                say_and_print("Введите имя объекта: ");
                fflush(stdout);
                read_line(name, sizeof(name));
                if (name[0] == '\0') 
                {
                    say_and_print("Пустое имя.\n");
                    break;
                }
                err_t rc = describe_object(akin, name);
                if (rc != OK) 
                    { say("Не удалось описать объект!"); printf("Не удалось описать объект \"%s\" (код %d).\n", name, rc); }
                break;
            }
            case 5: 
            {
                char obj1[512] = {  };
                char obj2[512] = {  };
                say_and_print("Введите первый объект: ");
                fflush(stdout);

                read_line(obj1, sizeof(obj1));
                say_and_print("Введите второй объект: ");
                fflush(stdout);

                read_line(obj2, sizeof(obj2));
                if (!obj1[0] || !obj2[0]) 
                {
                    say_and_print("Пустое имя объекта.\n");
                    break;
                }
                err_t rc = difference_in_objects(akin, obj1, obj2);
                if (rc != OK)
                    { say("Не удалось найти разницу"); 
                        printf("Не удалось сравнить \"%s\" и \"%s\" (код %d).\n", obj1, obj2, rc); }
                break;
            }
            case 0:
                running = 0;
                say_and_print("Почему ты от меня ушел? Я выслежу и найду тебя чтобы продолжить игру!\n");
                break;
            default:
                say_and_print("Неизвестный пункт меню.\n");
                break;
        }
    }
}

# SEARCHER
Searcher is a set of scripts aimed at generating a report on the activity of domain users in a working system. The set consists of two parts:

- the first one dedicated to servers based on linux systems, contains a script written in python3 whose task is to send a query to the domain controller and the response is saved to a JSON file in two versions, one working and the other with a timestamp for archiving

- the second dedicated to windows workstations, contains a package of scripts that read the previously created JSON file and process it in the form of an EXCEL report

###

Szperacz jest zestawem skryptów mających na celu generowanie raportu dotyczącego aktywności użytkowników domenowych w pracującym systemie. Zestaw składa się z dwóch części:

- pierwsza dedykowana pod serwery oparte na systemach linux, zawiera skrypt napisany w python3 którego zadaniem jest wysłanie zapytania do kontrolera domeny a odpowiedź zostaje zapisana do pliku JSON w dwóch wersjach, jednej roboczej i drugiej ze znacznikiem czasowym w celu archiwizacji

- druga dedykowana pod stacje robocze z systemem windows, zawiera paczkę skryptów które odczytują wcześniej utworzony plik JSON i przetwarzają go w formę raportu EXCEL
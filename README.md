## Ticket_server

# Task description

Network ticket reservation
Implement a UDP server that handles network ticket reservation for events. The server should be single-threaded and able to handle multiple clients simultaneously.

Server parameters
The server accepts the following parameters on the command line:

-f file - the name of the file with the event description, optionally preceded by the path indicating where to find the file, mandatory;
-p port - the port on which the server listens, optional, default 2022;
-t timeout - the time limit in seconds, optional, value range from 1 to 86400, default 5.
The server should thoroughly check the correctness of the parameters. Errors should be reported by printing a suitable message to the standard diagnostic output and terminating with a code of 1.

Messages exchanged between client and server
The following fields may occur in the messages exchanged between the client and the server:

message_id - 1 octet, binary field;
description_length - 1 octet, binary field, the number of octets in the description field;
description - event description, any non-empty text that does not contain the zero character or the newline character;
ticket_count - 2 octets, binary field;
event_id - 4 octets, binary field, a unique event identifier generated by the server, value range from 0 to 999999;
reservation_id - 4 octets, binary field, a unique reservation identifier generated by the server, value greater than 999999;
cookie - 48 octets, ASCII characters with codes ranging from 33 to 126, a unique, difficult-to-guess confirmation string generated by the server;
expiration_time - 8 octets, binary field, the number of seconds from the beginning of the Unix epoch;
ticket - 7 octets, ASCII characters, only digits and uppercase English letters, a unique ticket code generated by the server.
Values in multi-octet binary fields are stored in network byte order.

Messages sent by the client
The client sends the following messages (message name, field list, field values, description):

GET_EVENTS - message_id = 1, a request to send a list of events and the number of available tickets for each event;
GET_RESERVATION - message_id = 3, event_id, ticket_count > 0, a request to reserve the specified number of tickets for the indicated events;
GET_TICKETS - message_id = 5, reservation_id, cookie, a request to send the reserved tickets.
Messages sent by the server
The server sends the following messages (message name, field list, field values, description):

EVENTS - message_id = 2, a repeating sequence of event_id, ticket_count, description_length, description fields, a response to the GET_EVENTS message containing a list of event descriptions and the number of available tickets for each event;
RESERVATION - message_id = 4, reservation_id, event_id, ticket_count, cookie, expiration_time, a response to the GET_RESERVATION message confirming the reservation and containing the time until the reserved tickets must be collected;
TICKETS - message_id = 6, reservation_id, ticket_count > 0, ticket, ..., ticket, a response to the GET_TICKETS message containing ticket_count fields of the ticket type;
BAD_REQUEST - message_id = 255, event_id or reservation_id, a refusal to reserve tickets in response to the GET_RESERVATION or to send tickets in response to the GET_TICKETS request.
The EVENTS message must fit into a single UDP datagram. If the description of all events does not fit, then an EVENTS message containing as many (arbitrarily chosen) descriptions as possible should be sent.

# Treść zadania

Sieciowa rezerwacja biletów
Zaimplementuj serwer UDP obsługujący sieciową rezerwację biletów na wydarzenia. Serwer ma być jednowątkowy i powinien obsługiwać klientów symultanicznie.

Parametry serwera
Serwer akceptuje w linii poleceń następujące parametry:

-f file – nazwa pliku z opisem wydarzeń poprzedzona opcjonalnie ścieżką wskazującą, gdzie szukać tego pliku, obowiązkowy;
-p port – port, na którym nasłuchuje, opcjonalny, domyślnie 2022;
-t timeout – limit czasu w sekundach, opcjonalny, wartość z zakresu od 1 do 86400, domyślnie 5.
Serwer powinien dokładnie sprawdzać poprawność parametrów. Błędy powinien zgłaszać, wypisując stosowny komunikat na standardowe wyjście diagnostyczne i kończąc działanie z kodem 1.

Komunikaty wymieniane między klientem a serwerem
W komunikatach między klientem a serwerem mogą wystąpić następujące pola:

message_id – 1 oktet, pole binarne;
description_length– 1 oktet, pole binarne, liczba oktetów w polu description;
description – opis wydarzenia, dowolny niepusty tekst, niezawierający znaku o kodzie zero ani znaku przejścia do nowej linii;
ticket_count – 2 oktety, pole binarne;
event_id – 4 oktety, pole binarne, unikalny identyfikator wydarzenia, generowany przez serwer, wartość z zakresu od 0 do 999999;
reservation_id – 4 oktety, pole binarne, unikalny identyfikator rezerwacji, generowany przez serwer, wartość większa niż 999999;
cookie – 48 oktetów, znaki ASCII o kodach z zakresu od 33 do 126, unikalny, trudny do odgadnięcia napis potwierdzający rezerwację, generowany przez serwer;
expiration_time – 8 oktetów, pole binarne, liczba sekund od początku epoki uniksa;
ticket– 7 oktetów, znaki ASCII, tylko cyfry i wielkie litery alfabetu angielskiego, unikalny kod biletu, generowany przez serwer.
Wartości w binarnych polach wielooktetowych zapisuje się w porządku sieciowym.

Komunikaty wysyłane przez klienta
Klient wysyła następujące komunikaty (nazwa komunikatu, lista pól, wartości pól, opis):

GET_EVENTS – message_id = 1, prośba o przysłanie listy wydarzeń i liczb dostępnych biletów na poszczególne wydarzenia;
GET_RESERVATION – message_id = 3, event_id, ticket_count > 0, prośba o zarezerwowanie wskazanej liczby biletów na wskazane wydarzenia;
GET_TICKETS – message_id = 5, reservation_id, cookie, prośba o wysłanie zarezerwowanych biletów.
Komunikaty wysyłane przez serwer
Serwer wysyła następujące komunikaty (nazwa komunikatu, lista pól, wartości pól, opis):

EVENTS – message_id = 2, powtarzająca się sekwencja pól event_id, ticket_count, description_length, description, odpowiedź na komunikat GET_EVENTS zawierająca listę opisów wydarzeń i liczb dostępnych biletów na każde wydarzenie;
RESERVATION – message_id = 4, reservation_id, event_id, ticket_count, cookie, expiration_time, odpowiedź na komunikat GET_RESERVATION potwierdzająca rezerwację, zawierająca czas, do którego należy odebrać zarezerwowane bilety;
TICKETS – message_id = 6, reservation_id, ticket_count > 0, ticket, …, ticket, odpowiedź na komunikat GET_TICKETS zawierająca ticket_count pól typu ticket;
BAD_REQUEST – message_id = 255, event_id lub reservation_id, odmowa na prośbę zarezerwowania biletów GET_RESERVATION lub wysłania biletów GET_TICKETS.
Komunikat EVENTS musi się zmieścić w jednym datagramie UDP. Jeśli opis wszystkich wydarzeń nie mieści się, to należy wysłać komunikat EVENTS zawierający tyle (dowolnie wybranych) opisów, ile się zmieści.

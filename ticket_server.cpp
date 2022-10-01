#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <cstdint>
#include <ctime>
#include <vector>
#include <string>
#include <fstream>
#include <iostream>
#include <unordered_map>
#include <queue>
#include <limits>
#include <sys/stat.h>

#define GET_EVENTS_SIZE             1
#define BAD_REQUEST_SIZE            5
#define TICKET_SIZE                 7
#define GET_RESERVATION_SIZE        7
#define COOKIE_SIZE                 48
#define GET_TICKETS_SIZE            53
#define RESERVATION_SIZE            67

#define GET_EVENTS                  1
#define EVENTS                      2
#define GET_RESERVATION             3
#define RESERVATION                 4
#define GET_TICKETS                 5
#define TICKETS                     6
#define BAD_REQUEST                 255

#define DEFAULT_TIMEOUT             5
#define MIN_COOKIE_ASCII            33
#define MAX_COOKIE_ASCII            126
#define DEFAULT_PORT                2022
#define MAX_TICKETS                 9357
#define MAX_UDP_DATAGRAM            65507
#define MAX_TIMEOUT                 86400
#define INITIAL_RES_ID              999999
#define INITIAL_TICKET              "0000000"
#define CAPITAL_A                   'A'
#define CAPITAL_Z                   'Z'
#define ZERO_CZAR                   '0'
#define NINE_CHAR                   '9'
#define FILE_FLAG                   "-f"
#define TIMEOUT_FLAG                "-t"
#define PORT_FLAG                   "-p"

// funkcje sprawdzające błędy
// źródło: plik err.h udostępniony na laboratorium z sieci
#define ENSURE(x)                                                         \
    do {                                                                  \
        bool result = (x);                                                \
        if (!result) {                                                    \
            fprintf(stderr, "Error: %s was false in %s at %s:%d\n",       \
                #x, __func__, __FILE__, __LINE__);                        \
            exit(EXIT_FAILURE);                                           \
        }                                                                 \
    } while (0)

#define PRINT_ERRNO()                                                  \
    do {                                                               \
        if (errno != 0) {                                              \
            fprintf(stderr, "Error: errno %d in %s at %s:%d\n%s\n",    \
              errno, __func__, __FILE__, __LINE__, strerror(errno));   \
            exit(EXIT_FAILURE);                                        \
        }                                                              \
    } while (0)

#define CHECK_ERRNO(x)                                                             \
    do {                                                                           \
        errno = 0;                                                                 \
        (void) (x);                                                                \
        PRINT_ERRNO();                                                             \
    } while (0)

struct reservation;
struct event;

using reservation_map_t = std::unordered_map<uint32_t, reservation>;
using event_list_t = std::vector<event>;
using tickets_t = std::vector<std::string>;

// struktura przechowująca dane o wydarzeniach pobranych z pliku
struct event {
    uint32_t event_id;
    uint16_t available_tickets;
    uint8_t description_length;
    std::string description;
};

// struktura przechowująca parametry programu
struct parameters {
    char *filename;
    uint16_t port;
    uint32_t timeout;
};

// struktura przechowująca dane o rezerwacji
struct reservation {
    uint32_t event_id;
    uint16_t ticket_count;
    char cookie[COOKIE_SIZE];
    uint64_t expiration_time;
    tickets_t tickets;
};

// struktura przechowująca dane o rezerwacjach w systemie
// rezerwacje są podzielone na oczekujące i wypełnione
// (te, w których bilety zostały odebrane)
// dodatkowo przechowujemy timeout i kolejny bilet oraz id rezerwacji do przydzielenia
struct reservations_info {
    std::string next_ticket = INITIAL_TICKET;
    uint32_t next_reservation_id = INITIAL_RES_ID;
    uint32_t timeout = DEFAULT_TIMEOUT;
    reservation_map_t awaiting;
    reservation_map_t fulfilled;
    std::queue<uint32_t> id_timeout_queue; // kolejka do wydajnego usuwania przeterminowanych rezerwacji
};

// funkcja wiążąca gniazdo
// źródło: funkcja udostępniona na laboratorium z sieci
int bind_socket(uint16_t port) {
    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    ENSURE(socket_fd > 0);

    struct sockaddr_in server_address{};
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    server_address.sin_port = htons(port);

    CHECK_ERRNO(bind(socket_fd, (struct sockaddr *) &server_address,
                    (socklen_t) sizeof(server_address)));

    return socket_fd;
}

// funkcja wypisująca komunikat o przesłanej klientowi wiadomości
void print_sent_msg(std::string &message_type, char *client_ip, uint16_t client_port) {
    printf("Sent message %s to client %s:%u\n", message_type.c_str(), client_ip, client_port);
}

// funkcja wysyłająca wiadomość na wskazany adres klienta
// źródło: funkcja udostępniona na laboratorium z sieci
void send_message(int socket_fd, const struct sockaddr_in *client_address, void *message, size_t length) {

    uint8_t msg_id = *((uint8_t*) message);
    auto address_length = (socklen_t) sizeof(*client_address);
    int flags = 0;
    ssize_t sent_length = sendto(socket_fd, message, length, flags,
                                 (struct sockaddr *) client_address, address_length);

    char* client_ip = inet_ntoa(client_address->sin_addr);
    uint16_t client_port = ntohs(client_address->sin_port);
    std::string msg_type;
    if (msg_id == EVENTS) msg_type = "EVENTS";
    else if (msg_id == RESERVATION) msg_type = "RESERVATION";
    else if (msg_id == BAD_REQUEST) msg_type = "BAD_REQUEST";
    else if (msg_id == TICKETS) msg_type = "TICKETS";

    print_sent_msg(msg_type, client_ip, client_port);
    ENSURE(sent_length == (ssize_t) length);
}

// funkcja generująca losowe cookie
// wypełnia tablicę cookie wylosowanymi znakami z dozwolonego zakresu
void generate_random_cookie(char cookie[]) {
    for (size_t i = 0; i < COOKIE_SIZE; i++) {
        cookie[i] = MIN_COOKIE_ASCII +
                    (rand() % (MAX_COOKIE_ASCII - MIN_COOKIE_ASCII + 1));
    }
}

// funkcja wyliczająca kolejny numer biletu do użycia
// bilety są zapisami kolejnych liczb w systemie liczbowym o podstawie 36
std::string get_next_ticket(std::string &prev_ticket) {
    std::string new_ticket = prev_ticket;
    for (int i = TICKET_SIZE - 1; i >= 0; i--) {
        if (prev_ticket[i] == NINE_CHAR) {
            new_ticket[i] = CAPITAL_A;
            return new_ticket;
        }
        else if (prev_ticket[i] == CAPITAL_Z) { // wykonujemy "przeniesienie"
            new_ticket[i] = ZERO_CZAR; // musimy przejść kolejny obrót pętli
        }
        else {
            new_ticket[i] = prev_ticket[i] + 1;
            return new_ticket;
        }
    }

    return new_ticket;
}

// funkcja generująca ticket_count biletów
// w tym celu korzysta z powyższej funkcji get_next_ticket
tickets_t generate_tickets(uint16_t ticket_count, reservations_info &reservations) {
    tickets_t result(ticket_count);
    std::string new_ticket;
    for (size_t i = 0; i < ticket_count; i++) {
        new_ticket = reservations.next_ticket;
        reservations.next_ticket = get_next_ticket(reservations.next_ticket);
        result[i] = new_ticket;
    }
    return result;
}

// funkcja podające kolejne id rezerwacji do wykorzystania
uint32_t get_next_reservation_id(reservations_info &reservations) {
    uint32_t id = reservations.next_reservation_id + 1;
    reservations.next_reservation_id += 1;

    if (id == std::numeric_limits<uint32_t>::max()) {
        // to nie powinno się wydarzyć — numerów rezerwacji jest bardzo dużo
        fprintf(stderr, "another reservation is not possible.\n");
        exit(EXIT_FAILURE);
    }

    return id;
}

// funkcja dodająca do systemu nową rezerwację
// określa czas jej upłynięcia, generuje cookie
uint32_t make_reservation(uint32_t requested_event, uint16_t requested_tickets,
                          reservations_info &reservations) {

    reservation new_reservation{};
    uint32_t id = get_next_reservation_id(reservations);
    generate_random_cookie(new_reservation.cookie);

    new_reservation.event_id = requested_event;
    new_reservation.ticket_count = requested_tickets;
    new_reservation.expiration_time = time(nullptr) + reservations.timeout;
    reservations.awaiting.insert(std::make_pair(id, new_reservation));
    reservations.id_timeout_queue.push(id);

    return id;
}

// funkcja odbierająca wiadomość od klienta o wskazanym adresie
// źródło: funkcja udostępniona na laboratorium z sieci
// modyfikacja: funkcja od razu sprawdza pierwszy bajt otrzymanej wiadomości i zwraca go, jako message id
// długość odczytanej wiadomości jest zapisana na zmiennej read_length
uint8_t read_message(int socket_fd, struct sockaddr_in *client_address, void *buffer,
                     size_t max_length, size_t *read_length) {

    auto address_length = (socklen_t) sizeof(*client_address);
    int flags = 0;
    errno = 0;
    ssize_t len = recvfrom(socket_fd, buffer, max_length, flags,
                           (struct sockaddr *) client_address, &address_length);

    if (len < 0) PRINT_ERRNO();
    *read_length = (size_t) len;

    uint8_t msg_id = *((uint8_t*) buffer);
    return msg_id;
}

bool is_valid_event_id(uint32_t event_id, size_t events_number) {
    return (event_id < events_number); // eventy numeruję od 0 - taki warunek starczy
}

bool tickets_available(uint32_t requested_event, uint16_t requested_tickets, event_list_t &event_list) {
    return (event_list[requested_event].available_tickets >= requested_tickets);
}

// funkcja sprawdza, po kolei oczekujące rezerwacje
// usuwa z systemu te, które już wygasły
void check_timeouts(reservations_info &reservations, event_list_t &event_list) {
    uint64_t current_time;

    uint32_t curr_id;
    reservation curr_res;
    while(!reservations.id_timeout_queue.empty()) {
        curr_id = reservations.id_timeout_queue.front();
        if (reservations.awaiting.find(curr_id) != reservations.awaiting.end()) {
            curr_res = reservations.awaiting[curr_id];
            current_time = time(nullptr);
            if (curr_res.expiration_time <= current_time) {
                event_list[curr_res.event_id].available_tickets += curr_res.ticket_count;
                reservations.awaiting.erase(curr_id);
                reservations.id_timeout_queue.pop();
            }
            else break;
        }
        else reservations.id_timeout_queue.pop();
    }
}

// funkcja sprawdza, czy żądanie klienta get_reservation może zostać wykonane
bool verify_reservation_request(uint32_t requested_event, uint16_t requested_tickets,
                                event_list_t &event_list, reservations_info &reservations) {

    check_timeouts(reservations, event_list);
    if (requested_tickets == 0 || requested_tickets > MAX_TICKETS) return false;
    if (!is_valid_event_id(requested_event, event_list.size())) return false;
    if (!tickets_available(requested_event, requested_tickets, event_list)) return false;
    return true;
}

// pomocnicza funkcja — kopiuje size bajtów pod wskaźnikiem src
// do pamięci wskazywanej przez dest
// kolejno zwiększa wskaźnik dest o wartość size
void copy_mem_and_increase_dest(const void *src, char *&dest, size_t size) {
    memcpy(dest, src, size);
    (dest) += size;
}

// funkcja zapisuje do bufora komunikat bad request
// z wartością event_or_reservation_id
char *generate_bad_request_message(uint32_t event_or_reservation_id, char *buffer) {
    char *result_pointer = buffer;
    uint8_t msg_id = BAD_REQUEST;
    copy_mem_and_increase_dest(&msg_id, result_pointer, sizeof(uint8_t));

    uint32_t event_or_res_to_send = htonl(event_or_reservation_id);
    copy_mem_and_increase_dest(&event_or_res_to_send, result_pointer, sizeof(uint32_t));
    return buffer;
}

// funkcja zapisuje do bufora komunikat reservation oraz
// dodaje rezerwację do struktury reservations
char *generate_reservation_message(uint32_t requested_event, uint16_t requested_tickets,
                                   reservations_info &reservations, char *buffer) {

    char *result_pointer = buffer;
    uint8_t msg_id = RESERVATION;
    copy_mem_and_increase_dest(&msg_id, result_pointer, sizeof(uint8_t));

    uint32_t r_id = make_reservation(requested_event, requested_tickets, reservations);
    uint32_t r_id_to_send = htonl(r_id);
    copy_mem_and_increase_dest(&r_id_to_send, result_pointer, sizeof(uint32_t));

    uint32_t event_id = htonl(requested_event);
    copy_mem_and_increase_dest(&event_id, result_pointer, sizeof(uint32_t));

    uint16_t ticket_count = htons(requested_tickets);
    copy_mem_and_increase_dest(&ticket_count, result_pointer, sizeof(uint16_t));

    copy_mem_and_increase_dest(reservations.awaiting[r_id].cookie, result_pointer, COOKIE_SIZE);

    uint64_t expiration_time = htobe64(reservations.awaiting[r_id].expiration_time);
    copy_mem_and_increase_dest(&expiration_time, result_pointer, sizeof(uint64_t));

    return buffer;
}

// funkcja zapisuje do bufora komunikat tickets, korzystając z gotowych biletów
// podanych w argumencie
char *generate_tickets_message(uint32_t reservation_id, size_t &size, uint16_t ticket_count,
                               tickets_t &tickets, char *buffer) {

    size = sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint16_t) + ticket_count * TICKET_SIZE;
    char *result_ptr = buffer;

    uint8_t msg_id = TICKETS;
    copy_mem_and_increase_dest(&msg_id, result_ptr, sizeof(uint8_t));

    uint32_t res_id_to_send = htonl(reservation_id);
    copy_mem_and_increase_dest(&res_id_to_send, result_ptr, sizeof(uint32_t));
    uint16_t ticket_count_to_send = htons(ticket_count);
    copy_mem_and_increase_dest(&ticket_count_to_send, result_ptr, sizeof(uint16_t));

    for (size_t i = 0; i < ticket_count; i++)
        copy_mem_and_increase_dest(tickets[i].c_str(), result_ptr, TICKET_SIZE);

    return buffer;
}

// funkcja sprawdza poprawność komunikatu od klienta — get tickets
bool verify_tickets_request(uint32_t reservation_id, char cookie[], reservations_info &reservations,
                            bool &awaiting, event_list_t &event_list) {

    check_timeouts(reservations, event_list);
    if (reservations.awaiting.find(reservation_id) != reservations.awaiting.end()) {
        awaiting = true; // bilety będą odebrane po raz pierwszy
    }
    else if (reservations.fulfilled.find(reservation_id) == reservations.fulfilled.end()) {
        return false; // rezerwacji nie ma ani w oczekujących, ani w wypełnionych
    }

    // sprawdzamy poprawność podanego cookie
    if (awaiting) {
        if (strncmp(reservations.awaiting[reservation_id].cookie, cookie, COOKIE_SIZE) != 0) {
            return false;
        }
    } else {
        if (strncmp(reservations.fulfilled[reservation_id].cookie, cookie, COOKIE_SIZE) != 0) return false;
    }

    return true;
}

// funkcja rezerwuje bilety — wystarczy odjąć odpowiednią ilość od dostępnych biletów
// przechowywanych w strukturze event
void book_tickets(event_list_t &event_list, uint32_t event_id, uint16_t tickets) {
    event_list[event_id].available_tickets -= tickets;
}

// funkcja odczytuje treść wiadomości get_reservation od klienta
// kolejno decyduje jaki komunikat odesłać i generuje odpowiednią odpowiedź
char *get_answer_to_get_reservation(char *client_msg, size_t &size, event_list_t &event_list,
                                    reservations_info &reservations, char *buffer) {

    char *curr_pointer = client_msg;
    curr_pointer += sizeof (char);

    uint32_t requested_event = *((uint32_t *) (curr_pointer));
    requested_event = ntohl(requested_event);
    curr_pointer += (4 * sizeof(char));

    uint16_t requested_tickets = *((uint16_t*) (curr_pointer));
    requested_tickets = ntohs(requested_tickets);

    if (!verify_reservation_request(requested_event, requested_tickets, event_list, reservations)) {
        size = BAD_REQUEST_SIZE;
        return generate_bad_request_message(requested_event, buffer);
    }
    else {
        size = RESERVATION_SIZE;
        book_tickets(event_list, requested_event, requested_tickets);
        return generate_reservation_message(requested_event, requested_tickets, reservations, buffer);
    }
}

size_t get_event_size(event &event) {
    return sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint8_t) +
           event.description_length;
}

// funkcja odpowiada na komunikat od klienta get events
// umieszcza w buforze informacje o wszystkich eventach
char *get_answer_to_get_events(event_list_t &event_list, size_t &size, char *buffer) {
    char *curr_ptr = buffer;

    uint8_t msg_id = EVENTS;
    memcpy(curr_ptr, &msg_id, 1);
    curr_ptr += sizeof (uint8_t);
    size_t message_size = 1;
    size_t curr_event_size;

    for (auto & event : event_list) {
        curr_event_size = get_event_size(event);
        if (message_size + curr_event_size <= MAX_UDP_DATAGRAM) {
            uint32_t id = htonl(event.event_id);
            copy_mem_and_increase_dest(&id, curr_ptr, sizeof(uint32_t));

            uint16_t tickets = htons(event.available_tickets);
            copy_mem_and_increase_dest(&tickets, curr_ptr, sizeof(uint16_t));

            copy_mem_and_increase_dest(&event.description_length, curr_ptr, sizeof(uint8_t));
            copy_mem_and_increase_dest(event.description.c_str(), curr_ptr,
                                       event.description_length * sizeof(uint8_t));

            message_size += curr_event_size;
        }
    }
    size = message_size;
    return buffer;
}

// funkcja przenosi rezerwację do wypełnionych
// generuje bilety dla klienta
void fulfill_reservation(reservations_info &reservations, uint32_t id) {
    reservation fulfilled_res = reservations.awaiting[id];
    fulfilled_res.tickets = generate_tickets(fulfilled_res.ticket_count, reservations);
    reservations.awaiting.erase(id);
    reservations.fulfilled.insert(std::make_pair(id, fulfilled_res));
}

// funkcja odczytuje treść wiadomości get tickets od klienta,
// kolejno decyduje jaki komunikat odesłać i generuje odpowiednią odpowiedź
char *get_answer_to_get_tickets(char *client_msg, size_t &size, reservations_info &reservations,
                                event_list_t &event_list, char *buffer) {

    char *curr_pointer = client_msg;
    curr_pointer += sizeof (char);

    uint32_t reservation_id = *((uint32_t *) curr_pointer);
    reservation_id = ntohl(reservation_id);
    curr_pointer += sizeof(uint32_t);

    char cookie[COOKIE_SIZE];
    memcpy(cookie, curr_pointer, COOKIE_SIZE);

    bool awaiting = false;
    if (!verify_tickets_request(reservation_id, cookie, reservations, awaiting, event_list)) {
        size = BAD_REQUEST_SIZE;
        return generate_bad_request_message(reservation_id, buffer);
    }
    else {
        if (awaiting) // w tym przypadku należy wygenerować bilety
            fulfill_reservation(reservations, reservation_id);

        tickets_t tickets = reservations.fulfilled[reservation_id].tickets;
        uint16_t ticket_count = reservations.fulfilled[reservation_id].ticket_count;
        return generate_tickets_message(reservation_id, size, ticket_count, tickets, buffer);
    }
}

// funkcja przygotowująca odpowiedź na żądanie klienta
// zwraca wskaźnik na server_msg_buffer lub null, jeśli komunikat klienta jest niepoprawny
char *prepare_answer_message(uint8_t msg_id, event_list_t &event_list, size_t read_length, size_t &size,
                             char *client_msg, reservations_info &reservations, char *buffer) {
    switch (msg_id) {
        case GET_EVENTS:
            if (read_length != GET_EVENTS_SIZE) return nullptr;
            return get_answer_to_get_events(event_list, size, buffer);
        case GET_RESERVATION:
            if (read_length != GET_RESERVATION_SIZE) return nullptr;
            return get_answer_to_get_reservation(client_msg, size, event_list, reservations, buffer);
        case GET_TICKETS:
            if (read_length != GET_TICKETS_SIZE) return nullptr;
            return get_answer_to_get_tickets(client_msg, size, reservations, event_list, buffer);
        default:
            return nullptr;
    }
}

// funkcja wczytująca wydarzenia z pliku do vectora
// uzupełnia wszystkie potrzebne informacje o wydarzeniu
event_list_t get_event_list(char *filename) {
    std::ifstream file;
    file.open(filename);
    if (!file) {
        fprintf(stderr, "Error in opening file %s.\n", filename);
        exit(EXIT_FAILURE);
    }

    std::string current_line;
    uint32_t event_id = 0;
    event_list_t events;
    event new_event{};
    while (getline(file, current_line)) {
        new_event.description_length = current_line.size();
        new_event.description = current_line;
        new_event.event_id = event_id;

        getline(file, current_line);
        char *end;
        new_event.available_tickets = (uint16_t) std::strtoul(current_line.c_str(), &end, 10);
        events.push_back(new_event);
        event_id++;
    }

    file.close();
    return events;
}

// funkcja sprawdzająca, czy napis reprezentuje liczbę
bool is_number(char *string) {
    for (int i = 0; string[i] != 0; i++) {
        if (!std::isdigit(string[i])) return false;
    }
    return true;
}

// funkcja sprawdzająca poprawność i odczytująca podany port
uint16_t read_port(char *string) {
    errno = 0;
    if (!is_number(string)) {
        fprintf(stderr, "%s is not a valid port number\n", string);
        exit(EXIT_FAILURE);
    }

    unsigned long port = strtoul(string, nullptr, 10);
    PRINT_ERRNO();
    if (port > UINT16_MAX) {
        fprintf(stderr, "%lu is not a valid port number\n", port);
        exit(EXIT_FAILURE);
    }
    return (uint16_t) port;
}

// funkcja sprawdzająca poprawność i odczytująca podany timeout
uint32_t read_timeout(char *string) {
    errno = 0;
    if (!is_number(string)) {
        fprintf(stderr, "%s is not a valid port number\n", string);
        exit(EXIT_FAILURE);
    }

    unsigned long timeout = strtoul(string, nullptr, 10);
    PRINT_ERRNO();
    if (timeout > MAX_TIMEOUT || timeout == 0) {
        fprintf(stderr, "%lu is not a valid timeout\n", timeout);
        exit(EXIT_FAILURE);
    }
    return (uint32_t) timeout;
}

// funkcja sprawdzająca poprawność i odczytująca podany plik
char *read_file(char *string) {
    struct stat stat_buff{};
    if (stat(string, &stat_buff) != 0) {
        fprintf(stderr, "File not found\n");
        exit(EXIT_FAILURE);
    }

    if (!S_ISREG(stat_buff.st_mode)) {
        fprintf(stderr, "Given file is not a file\n");
        exit(EXIT_FAILURE);
    }

    return string;
}

// funkcja generująca error opisujący sposób użycia programu
void bad_usage_error(char *program_name) {
    fprintf(stderr, "Usage: %s -f <path to events file> [-p <port>] [-t <timeout>]\n", program_name);
    exit(EXIT_FAILURE);
}

// funkcja pobierająca parametry programu z wejścia
// oraz sprawdzająca ich poprawność
parameters get_and_verify_parameters(int argc, char *argv[]) {
    parameters params{};

    if (argc < 3)
        bad_usage_error(argv[0]);

    params.port = DEFAULT_PORT;
    params.timeout = DEFAULT_TIMEOUT;
    bool file_provided = false;

    int arg_i = 1;
    while (arg_i < argc) {
        arg_i++;
        if (arg_i >= argc)
            bad_usage_error(argv[0]);

        if (strcmp(argv[arg_i - 1], FILE_FLAG) == 0) {
            params.filename = read_file(argv[arg_i]);
            file_provided = true;
        }
        else if (strcmp(argv[arg_i - 1], PORT_FLAG) == 0) {
            params.port = read_port(argv[arg_i]);
        }
        else if (strcmp(argv[arg_i - 1], TIMEOUT_FLAG) == 0) {
            params.timeout = read_timeout(argv[arg_i]);
        }
        else bad_usage_error(argv[0]);

        arg_i++;
    }

    if (!file_provided) {
        fprintf(stderr, "No events file provided!.\n");
        exit(EXIT_FAILURE);
    }
    return params;
}

int main(int argc, char *argv[]) {
    srand(time(nullptr)); // do generowania cookie
    parameters parameters = get_and_verify_parameters(argc, argv);
    printf("Listening on port %u\n", parameters.port);

    event_list_t events = get_event_list(parameters.filename);
    int socket_fd = bind_socket(parameters.port);
    struct sockaddr_in client_address{};
    size_t read_length = 1;
    uint8_t msg_id;

    reservations_info reservations;
    reservations.timeout = parameters.timeout;
    char client_msg_buffer[MAX_UDP_DATAGRAM]; // dla przejrzystości dwa osobne bufory
    char server_msg_buffer[MAX_UDP_DATAGRAM];
    do {
        memset(client_msg_buffer, 0, sizeof(client_msg_buffer));
        msg_id = read_message(socket_fd, &client_address, client_msg_buffer, MAX_UDP_DATAGRAM, &read_length);
        char* client_ip = inet_ntoa(client_address.sin_addr);
        uint16_t client_port = ntohs(client_address.sin_port);
        printf("Received %zd bytes from client %s:%u\n", read_length, client_ip, client_port);

        size_t size = 0;
        memset(server_msg_buffer, 0, sizeof(server_msg_buffer));
        void *answer = prepare_answer_message(msg_id, events, read_length, size, client_msg_buffer,
                                              reservations, server_msg_buffer);
        if (answer) send_message(socket_fd, &client_address, answer, size);

    } while (true);

    CHECK_ERRNO(close(socket_fd));
    return 0;
}

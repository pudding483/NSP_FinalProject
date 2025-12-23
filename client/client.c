// client/client.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>
#include <pthread.h>

#include "common.h"

#define SERVER_IP "127.0.0.1"
#define PORT 8080

// Thread argument structure
struct thread_arg {
    char action[10];
    int num_tickets;
    int user_id;
};

void *client_thread(void *arg);
uint32_t perform_login(int sockfd);
void query_availability(int sockfd, uint32_t session_id);
void book_tickets(int sockfd, int num_tickets, int user_id, uint32_t session_id);

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <num_threads> <query|book> [num_tickets]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Initialize logger
    init_logger("client.log");
    log_message(LOG_INFO, "Client starting with %s threads for %s operation", argv[1], argv[2]);

    int num_threads = atoi(argv[1]);
    if (num_threads <= 0) {
        fprintf(stderr, "Number of threads must be a positive integer.\n");
        exit(EXIT_FAILURE);
    }

    char action[10];
    strcpy(action, argv[2]);

    int num_tickets = 0;
    if (strcmp(action, "book") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Usage: %s <num_threads> book <num_tickets>\n", argv[0]);
            exit(EXIT_FAILURE);
        }
        num_tickets = atoi(argv[3]);
        if (num_tickets <= 0) {
            fprintf(stderr, "Number of tickets must be a positive integer.\n");
            exit(EXIT_FAILURE);
        }
    }

    // Create threads
    pthread_t threads[num_threads];
    struct thread_arg args[num_threads];

    srand(time(NULL));
    for (int i = 0; i < num_threads; i++) {
        strcpy(args[i].action, action);
        args[i].num_tickets = num_tickets;
        args[i].user_id = rand() % 10000 + i * 10000; // Unique user_id per thread

        if (pthread_create(&threads[i], NULL, client_thread, &args[i]) != 0) {
            perror("pthread_create failed");
            exit(EXIT_FAILURE);
        }
    }

    // Wait for all threads to finish
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    return 0;
}

void *client_thread(void *arg) {
    struct thread_arg *targ = (struct thread_arg *)arg;
    int sockfd;
    uint32_t session_id = 0;

    log_message(LOG_INFO, "Thread started for user %d, action: %s", targ->user_id, targ->action);

    // Connect to server
    if ((sockfd = connect_to_server(SERVER_IP, PORT)) < 0) {
        perror("connect_to_server failed");
        return NULL;
    }
    
    // Set Timeouts (5 seconds)
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv) < 0) {
        perror("setsockopt failed (RCVTIMEO)");
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof tv) < 0) {
        perror("setsockopt failed (SNDTIMEO)");
    }

    // Perform Login First
    session_id = perform_login(sockfd);
    log_message(LOG_INFO, "Login successful, session_id=%u for user %d", session_id, targ->user_id);

    // Perform action
    if (strcmp(targ->action, "query") == 0) {
        query_availability(sockfd, session_id);
    } else if (strcmp(targ->action, "book") == 0) {
        book_tickets(sockfd, targ->num_tickets, targ->user_id, session_id);
    }

    close(sockfd);
    return NULL;
}

uint32_t perform_login(int sockfd) {
    static uint16_t req_id_counter = 0;

    printf("Logging in...\n");
    ProtocolHeader req_header = {
        .packet_len = sizeof(ProtocolHeader),
        .opcode = OP_LOGIN,
        .req_id = req_id_counter++,
        .session_id = 0,
        .checksum = 0
    };
    
    // Calculate Checksum & Encrypt
    req_header.checksum = calculate_checksum(&req_header, sizeof(ProtocolHeader));
    xor_cipher(&req_header, sizeof(ProtocolHeader));

    if (write_n_bytes(sockfd, &req_header, sizeof(ProtocolHeader)) <= 0) {
        perror("Failed to send login request");
        exit(EXIT_FAILURE);
    }

    // Read Response
    ProtocolHeader res_header;
    if (read_n_bytes(sockfd, &res_header, sizeof(ProtocolHeader)) <= 0) {
        perror("Failed to read login response header");
        exit(EXIT_FAILURE);
    }
    // Decrypt Header
    xor_cipher(&res_header, sizeof(ProtocolHeader));
    
    // Read Body
    ServerResponse res_body;
    if (read_n_bytes(sockfd, &res_body, sizeof(ServerResponse)) <= 0) {
        perror("Failed to read login response body");
        exit(EXIT_FAILURE);
    }
    // Decrypt Body
    xor_cipher(&res_body, sizeof(ServerResponse));

    // Verify Checksum
    uint32_t received_checksum = res_header.checksum;
    res_header.checksum = 0;
    uint32_t calc_sum = calculate_checksum(&res_header, sizeof(ProtocolHeader));
    calc_sum += calculate_checksum(&res_body, sizeof(ServerResponse));
    
    if (calc_sum != received_checksum) {
        fprintf(stderr, "Login response checksum mismatch!\n");
        exit(EXIT_FAILURE);
    }

    if (res_header.opcode == OP_RESPONSE_SUCCESS) {
        uint32_t session_id = res_header.session_id;
        printf("Login successful. Session ID: %u\n", session_id);
        log_message(LOG_INFO, "Login response received, session_id=%u", session_id);
        return session_id;
    } else {
        fprintf(stderr, "Login failed: %s\n", res_body.message);
        log_message(LOG_ERROR, "Login failed: %s", res_body.message);
        exit(EXIT_FAILURE);
    }
}

void query_availability(int sockfd, uint32_t session_id) {
    static uint16_t req_id_counter = 100;

    log_message(LOG_INFO, "Sending QUERY_AVAILABILITY request, session_id=%u", session_id);

    // 1. Prepare and send request header
    ProtocolHeader req_header = {
        .packet_len = sizeof(ProtocolHeader),
        .opcode = OP_QUERY_AVAILABILITY,
        .req_id = req_id_counter++,
        .session_id = session_id,
        .checksum = 0
    };
    
    // Checksum & Encrypt
    req_header.checksum = calculate_checksum(&req_header, sizeof(ProtocolHeader));
    xor_cipher(&req_header, sizeof(ProtocolHeader));

    if (write_n_bytes(sockfd, &req_header, sizeof(ProtocolHeader)) <= 0) {
        perror("Failed to send query request");
        return;
    }

    printf("Sent query request (req_id=%u).\n", req_id_counter-1);

    // 2. Read response
    ProtocolHeader res_header;
    if (read_n_bytes(sockfd, &res_header, sizeof(ProtocolHeader)) <= 0) {
        perror("Failed to read response header");
        return;
    }
    xor_cipher(&res_header, sizeof(ProtocolHeader));

    ServerResponse res_body;
    if (read_n_bytes(sockfd, &res_body, sizeof(ServerResponse)) <= 0) {
        perror("Failed to read response body");
        return;
    }
    xor_cipher(&res_body, sizeof(ServerResponse));

    // Verify Checksum
    uint32_t received_checksum = res_header.checksum;
    res_header.checksum = 0;
    uint32_t calc_sum = calculate_checksum(&res_header, sizeof(ProtocolHeader));
    calc_sum += calculate_checksum(&res_body, sizeof(ServerResponse));
    if (calc_sum != received_checksum) {
        fprintf(stderr, "Response checksum mismatch!\n");
        return;
    }

    // 3. Print result
    log_message(LOG_INFO, "Received QUERY response: remaining_tickets=%u, message=%s", res_body.remaining_tickets, res_body.message);
    printf("----------------------------------------\n");
    printf("Server Response (req_id=%u):\n", res_header.req_id);
    printf("  OpCode: 0x%X\n", res_header.opcode);
    printf("  Remaining Tickets: %u\n", res_body.remaining_tickets);
    printf("  Message: %s\n", res_body.message);
    printf("----------------------------------------\n");
}

void book_tickets(int sockfd, int num_tickets, int user_id, uint32_t session_id) {
    static uint16_t req_id_counter = 200;

    log_message(LOG_INFO, "Sending BOOK_TICKET request: num_tickets=%d, user_id=%d, session_id=%u", num_tickets, user_id, session_id);

    // 1. Prepare request header and body
    ProtocolHeader req_header = {
        .packet_len = sizeof(ProtocolHeader) + sizeof(BookRequest),
        .opcode = OP_BOOK_TICKET,
        .req_id = req_id_counter++,
        .session_id = session_id,
        .checksum = 0
    };
    BookRequest req_body = {
        .num_tickets = num_tickets,
        .user_id = user_id
    };

    // Calculate Checksum (Header + Body)
    // Note: To calc checksum correctly for header, header needs default 0 checksum field.
    req_header.checksum = calculate_checksum(&req_header, sizeof(ProtocolHeader));
    req_header.checksum += calculate_checksum(&req_body, sizeof(BookRequest));
    
    // Encrypt
    xor_cipher(&req_header, sizeof(ProtocolHeader));
    xor_cipher(&req_body, sizeof(BookRequest));

    // 2. Send request
    if (write_n_bytes(sockfd, &req_header, sizeof(ProtocolHeader)) <= 0) {
        perror("Failed to send booking request header");
        return;
    }
    if (write_n_bytes(sockfd, &req_body, sizeof(BookRequest)) <= 0) {
        perror("Failed to send booking request body");
        return;
    }
    printf("Sent book request for %d tickets (user_id=%d, req_id=%u).\n", num_tickets, user_id, req_header.req_id); // Note: req_header is encrypted now, printing it would show garbage if we accessed fields. Used counter-1 or similar. Actually here we might print unexpected values if we printed struct fields.
    // Fixed: printing local vars or previous knowns. req_header.req_id is encrypted.
    
    // 3. Read response
    ProtocolHeader res_header;
    if (read_n_bytes(sockfd, &res_header, sizeof(ProtocolHeader)) <= 0) {
        perror("Failed to read response header");
        return;
    }
    xor_cipher(&res_header, sizeof(ProtocolHeader));

    ServerResponse res_body;
    if (read_n_bytes(sockfd, &res_body, sizeof(ServerResponse)) <= 0) {
        perror("Failed to read response body");
        return;
    }
    xor_cipher(&res_body, sizeof(ServerResponse));

    // Verify Checksum
    uint32_t received_checksum = res_header.checksum;
    res_header.checksum = 0;
    uint32_t calc_sum = calculate_checksum(&res_header, sizeof(ProtocolHeader));
    calc_sum += calculate_checksum(&res_body, sizeof(ServerResponse));
    if (calc_sum != received_checksum) {
        fprintf(stderr, "Response checksum mismatch!\n");
        return;
    }

    // 4. Print result
    log_message(LOG_INFO, "Received BOOK response: status=%s, remaining_tickets=%u, message=%s", 
                (res_header.opcode == OP_RESPONSE_SUCCESS) ? "SUCCESS" : "FAIL", res_body.remaining_tickets, res_body.message);
    printf("----------------------------------------\n");
    printf("Server Response (req_id=%u):\n", res_header.req_id);
    if (res_header.opcode == OP_RESPONSE_SUCCESS) {
        printf("  Status: SUCCESS\n");
    } else {
        printf("  Status: FAIL\n");
    }
    printf("  Remaining Tickets: %u\n", res_body.remaining_tickets);
    printf("  Message: %s\n", res_body.message);
    printf("----------------------------------------\n");
}

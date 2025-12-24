// server/server.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/shm.h>
#include <sys/sem.h>
#include <sys/wait.h>

#include "common.h"

#define PORT 8080
#define MAX_PENDING_CONNECTIONS 5
#define MAX_SESSIONS 100

// Shared data structure
struct shared_data {
    int total_tickets;
    uint32_t active_sessions[MAX_SESSIONS];
    int session_count;
};

// Shared memory and semaphore keys
#define SHM_KEY 1234
#define SEM_KEY 5678

// Global pointers to shared memory
struct shared_data *shared;
int sem_id;
int server_delay = 0; // Simulation delay in seconds

// Semaphore operations
void sem_lock() {
    struct sembuf sb = {0, -1, 0};
    semop(sem_id, &sb, 1);
}

void sem_unlock() {
    struct sembuf sb = {0, 1, 0};
    semop(sem_id, &sb, 1);
}

void add_session(uint32_t session_id) {
    sem_lock();
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (shared->active_sessions[i] == 0) {
            shared->active_sessions[i] = session_id;
            shared->session_count++;
            break;
        }
    }
    sem_unlock();
}

int is_valid_session(uint32_t session_id) {
    if (session_id == 0) return 0;
    int found = 0;
    sem_lock();
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (shared->active_sessions[i] == session_id) {
            found = 1;
            break;
        }
    }
    sem_unlock();
    return found;
}

void handle_connection(int client_socket);

int main() {
    int server_fd, client_socket;
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    int shm_id;

    // Initialize logger
    init_logger("server.log");
    log_message(LOG_INFO, "Server starting up");

    // Create shared memory
    shm_id = shmget(SHM_KEY, sizeof(struct shared_data), IPC_CREAT | 0666);
    if (shm_id < 0) {
        perror("shmget failed");
        exit(EXIT_FAILURE);
    }
    shared = (struct shared_data *)shmat(shm_id, NULL, 0);
    if (shared == (struct shared_data *)-1) {
        perror("shmat failed");
        exit(EXIT_FAILURE);
    }

    // Initialize shared data
    shared->total_tickets = 100;
    memset(shared->active_sessions, 0, sizeof(shared->active_sessions));
    shared->session_count = 0;

    // Create semaphore
    sem_id = semget(SEM_KEY, 1, IPC_CREAT | 0666);
    if (sem_id < 0) {
        perror("semget failed");
        exit(EXIT_FAILURE);
    }
    // Initialize semaphore to 1
    semctl(sem_id, 0, SETVAL, 1);

    // Create server socket
    if ((server_fd = create_server_socket(PORT)) < 0) {
        perror("create_server_socket failed");
        exit(EXIT_FAILURE);
    }

    // Check for Simulation Delay
    char *delay_env = getenv("SERVER_DELAY");
    if (delay_env) {
        server_delay = atoi(delay_env);
        printf("[TEST MODE] Server Response Delay set to %d seconds.\n", server_delay);
    }

    printf("Server listening on port %d\n", PORT);
    printf("Initial tickets: %d\n", shared->total_tickets);

    // 4. Accept connections in a loop
    while (1) {
        if ((client_socket = accept(server_fd, (struct sockaddr *)&client_addr, &client_addr_len)) < 0) {
            perror("accept failed");
            continue; // Continue to next iteration
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        printf("Connection accepted from %s:%d\n", client_ip, ntohs(client_addr.sin_port));
        log_message(LOG_INFO, "Accepted connection from %s:%d", client_ip, ntohs(client_addr.sin_port));

        // Fork a child process to handle the connection
        pid_t pid = fork();
        if (pid < 0) {
            perror("fork failed");
            close(client_socket);
            continue;
        } else if (pid == 0) {
            // Child process
            close(server_fd); // Child doesn't need the listening socket

            // Set Timeout (10 seconds)
            struct timeval tv;
            tv.tv_sec = 10;
            tv.tv_usec = 0;
            if (setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv) < 0) {
                perror("setsockopt failed (RCVTIMEO)");
            }

            // Handle the connection
            handle_connection(client_socket);
            close(client_socket);
            exit(0);
        } else {
            // Parent process
            close(client_socket); // Parent doesn't need the client socket
            // Continue to accept next connection
        }
    }

    close(server_fd);
    return 0;
}

void handle_connection(int client_socket) {
    ProtocolHeader header;
    int read_ret;

    // Loop to handle multiple requests from the same client
    while ((read_ret = read_n_bytes(client_socket, &header, sizeof(ProtocolHeader))) > 0) {
        
        // 1. Decrypt Header
        xor_cipher(&header, sizeof(ProtocolHeader));

        // 2. Verify Checksum (Header part)
        // Note: For simplicity, we assume checksum was calculated on cleartext. 
        // We need to re-calculate it. 
        // But since we need the body to fully verify, we'll verify after reading body if needed.
        // Or we can assume Checksum covers Header+Body.
        
        // Let's read the body first if there is one
        void *body_buffer = NULL;
        int body_len = header.packet_len - sizeof(ProtocolHeader);
        if (body_len > 0) {
            body_buffer = malloc(body_len);
            if (read_n_bytes(client_socket, body_buffer, body_len) <= 0) {
                perror("Failed to read body");
                free(body_buffer);
                return;
            }
            // Decrypt Body
            xor_cipher(body_buffer, body_len);
        }

        // 3. Verify Checksum (Full Packet)
        uint32_t received_checksum = header.checksum;
        header.checksum = 0; // Zero out to calculate
        uint32_t calc_sum = calculate_checksum(&header, sizeof(ProtocolHeader));
        if (body_buffer) {
            calc_sum += calculate_checksum(body_buffer, body_len);
        }
        
        if (calc_sum != received_checksum) {
            printf("Checksum mismatch! Expected %u, got %u\n", received_checksum, calc_sum);
            if (body_buffer) free(body_buffer);
            close(client_socket);
            return;
        }
        // Restore checksum (optional, but good for debugging if we print it)
        header.checksum = received_checksum; 

        printf("Received request: packet_len=%u, opcode=0x%X, req_id=%u, session_id=%u\n",
               header.packet_len, header.opcode, header.req_id, header.session_id);
        log_message(LOG_INFO, "Received request: opcode=0x%X, req_id=%u, session_id=%u", header.opcode, header.req_id, header.session_id);

        ServerResponse response;
        memset(&response, 0, sizeof(ServerResponse)); // Clear response buffer

        // 4. Validate Session (unless Login)
        if (header.opcode != OP_LOGIN && !is_valid_session(header.session_id)) {
            printf("Invalid Session ID: %u\n", header.session_id);
            header.opcode = OP_RESPONSE_FAIL;
            strcpy(response.message, "Invalid Session ID. Please Login.");
            // Proceed to send response
        } else {
            switch (header.opcode) {
                case OP_LOGIN: {
                    log_message(LOG_INFO, "Processing LOGIN request");
                    // Generate new Session ID
                    uint32_t new_session_id = (rand() % 900000) + 100000;
                    add_session(new_session_id);
                    
                    // We reuse ServerResponse to send back session_id in remaining_tickets field? 
                    // Or define a new LoginResponse? 
                    // For simplicity, let's use the 'message' or 'remaining_tickets' field hacks, 
                    // or just assume the client looks at the `session_id` field in the RESPONSE HEADER?
                    // YES! The response header should carry the session_id back.
                    
                    header.session_id = new_session_id; // Set for response
                    header.opcode = OP_RESPONSE_SUCCESS;
                    strcpy(response.message, "Login Successful");
                    response.remaining_tickets = 0;
                    log_message(LOG_INFO, "Login successful, session_id=%u", new_session_id);
                    break;
                }

                case OP_QUERY_AVAILABILITY: {
                    log_message(LOG_INFO, "Processing QUERY_AVAILABILITY request");
                    sem_lock();
                    response.remaining_tickets = shared->total_tickets;
                    sem_unlock();

                    strcpy(response.message, "Query successful.");
                    header.opcode = OP_RESPONSE_SUCCESS;
                    break;
                }

                case OP_BOOK_TICKET: {
                    log_message(LOG_INFO, "Processing BOOK_TICKET request");
                    if (!body_buffer) {
                        header.opcode = OP_RESPONSE_FAIL;
                        strcpy(response.message, "Missing body.");
                        break;
                    }
                    BookRequest *req_body = (BookRequest *)body_buffer;
                    
                    sem_lock();
                    if ((unsigned int)shared->total_tickets >= req_body->num_tickets) {
                        shared->total_tickets -= req_body->num_tickets;
                        response.remaining_tickets = shared->total_tickets;
                        sprintf(response.message, "Booking successful for user %u.", req_body->user_id);
                        header.opcode = OP_RESPONSE_SUCCESS;
                        log_message(LOG_INFO, "Booking successful: %d tickets for user %u, remaining %d", req_body->num_tickets, req_body->user_id, shared->total_tickets);
                    } else {
                        response.remaining_tickets = shared->total_tickets;
                        sprintf(response.message, "Booking failed: not enough tickets.");
                        header.opcode = OP_RESPONSE_FAIL;
                        log_message(LOG_ERROR, "Booking failed: not enough tickets, requested %d, available %d", req_body->num_tickets, shared->total_tickets);
                    }
                    sem_unlock();
                    break;
                }

                default: {
                    printf("Unknown opcode: 0x%X\n", header.opcode);
                    log_message(LOG_ERROR, "Unknown opcode: 0x%X", header.opcode);
                    header.opcode = OP_RESPONSE_FAIL;
                    strcpy(response.message, "Unknown operation.");
                    break;
                }
            }
        }

        if (body_buffer) free(body_buffer);

        // 5. Send Response
        header.packet_len = sizeof(ProtocolHeader) + sizeof(ServerResponse);
        header.checksum = 0;
        
        // Calculate Checksum for Response
        uint32_t res_sum = calculate_checksum(&header, sizeof(ProtocolHeader));
        res_sum += calculate_checksum(&response, sizeof(ServerResponse));
        header.checksum = res_sum;

        // Encrypt Response
        xor_cipher(&header, sizeof(ProtocolHeader));
        xor_cipher(&response, sizeof(ServerResponse));

        // Simulate Delay if configured
        if (server_delay > 0) {
            printf("[TEST] Sleeping for %d seconds before response...\n", server_delay);
            sleep(server_delay);
        }

        write_n_bytes(client_socket, &header, sizeof(ProtocolHeader));
        write_n_bytes(client_socket, &response, sizeof(ServerResponse));
    }

    if (read_ret == 0) {
        printf("Client disconnected.\n");
    } else {
        perror("read_n_bytes failed");
    }

    close(client_socket);
}

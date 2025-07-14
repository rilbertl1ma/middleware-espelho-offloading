#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#define MAX_LINE 512
#define MAX_ENTRIES 100
#define MAX_OUTPUT_IPS 4
#define CMD "docker logs -f espelho"
#define OUTPUT_FILE "saida.txt"
#define FIXED_IP "192.168.56.102"
#define PREFIX "table_add espelho_udp forwardDecapture"

typedef struct {
    char ip1[32];
    int porta1;
    int porta2;
    char ip2s[MAX_OUTPUT_IPS][32];
    int porta3s[MAX_OUTPUT_IPS];
    char macs[MAX_OUTPUT_IPS][32];
    int count;
    char fluxo[17];  // nome do fluxo
} LogEntry;

typedef struct {
    int thread_id;
    char fluxo[17];
    char ip1[32];
    int porta1;
    int porta_set;
} FluxoTemp;

typedef struct {
    int thread_id;
    char ip2[32];
    char fluxo[17];  // depois de preenchido
    int fluxo_set;
    int porta3;
    int porta_set;
} SubscriberTemp;

SubscriberTemp subs_temp[MAX_ENTRIES];
int subs_count = 0;

LogEntry entries[MAX_ENTRIES];
int entry_count = 0;

FluxoTemp fluxos_temp[MAX_ENTRIES];
int fluxos_count = 0;

void trim_newline(char *str) {
    str[strcspn(str, "\n")] = '\0';
}

int match_entry(const char *ip1, int porta1, int porta2) {
    for (int i = 0; i < entry_count; ++i) {
        if (entries[i].porta2 == porta2 && strcmp(entries[i].ip1, ip1) == 0 && entries[i].porta1 == porta1) {
            return i;
        }
    }
    return -1;
}

const char* find_fluxo_by_ip_porta2(const char* ip1, int porta2) {
    for (int i = 0; i < entry_count; ++i) {
        if (entries[i].porta2 == porta2 && strcmp(entries[i].ip1, ip1) == 0) {
            return entries[i].fluxo;
        }
    }
    return "";
}

void print_all_subscribers() {
    printf("=== Lista de Subscribers ===\n");
    for (int i = 0; i < subs_count; ++i) {
        printf("Subscriber #%d\n", i + 1);
        printf("  Thread ID : %d\n", subs_temp[i].thread_id);
        printf("  IP2       : %s\n", subs_temp[i].ip2);
        printf("  Fluxo Set : %d\n", subs_temp[i].fluxo_set);
        printf("  Fluxo     : %s\n", subs_temp[i].fluxo_set ? subs_temp[i].fluxo : "(não definido ainda)");
	printf("  Porta     : %d\n", subs_temp[i].porta3);
	printf("  Porta Set : %d\n", subs_temp[i].porta_set);
        printf("-----------------------------\n");
    }
}

void print_all_publishers() {
    printf("=== Lista de Publishers ===\n");
    for (int i = 0; i < subs_count; ++i) {
        printf("Publisher #%d\n", i + 1);
        printf("  Thread ID : %d\n", fluxos_temp[i].thread_id);
        printf("  IP1       : %s\n", fluxos_temp[i].ip1);
        printf("  Fluxo     : %s\n", fluxos_temp[i].fluxo);
	printf("  Porta     : %d\n", fluxos_temp[i].porta1);
	printf("  Porta Set : %d\n", fluxos_temp[i].porta_set);
        printf("-----------------------------\n");
    }
}

void get_mac_from_ip(const char *ip, char *mac_out) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "sudo ip neigh show %s | awk '{print $5}'", ip);
    FILE *fp = popen(cmd, "r");
    if (fp == NULL || fgets(mac_out, 32, fp) == NULL) {
        strcpy(mac_out, "00:00:00:00:00:00");
    } else {
        mac_out[strcspn(mac_out, "\n")] = 0;
    }
    if (fp) pclose(fp);
}

void handle_subscriber_connection(const char *line) {
    int thread_id;
    char ip2[32];
    if (sscanf(line, "%d : main_subscriber : Subscriber conectou; %31[^:]:", &thread_id, ip2) == 2) {

	printf("Subscriber -> Thread: %d --- IP: %s\n", thread_id, ip2);

        for (int i = 0; i < subs_count; ++i) {
            if (subs_temp[i].thread_id == thread_id)
                return;  // já existe
        }
        SubscriberTemp st;
        st.thread_id = thread_id;
        strncpy(st.ip2, ip2, 31);
        st.fluxo_set = 0;
        subs_temp[subs_count++] = st;
    }
}

void handle_proxy_info(const char *line) {
    char fluxo[17], ip2[32];
    if (sscanf(line, "1 : thread_mesa_mensagens : Fazendo proxy do %16s para o endereço %31s", fluxo, ip2) == 2) {
	
	printf("Subscriber -> Fluxo: %s --- IP: %s\n", fluxo, ip2);

        for (int i = 0; i < subs_count; ++i) {
            if (!subs_temp[i].fluxo_set && strcmp(subs_temp[i].ip2, ip2) == 0) {
                strncpy(subs_temp[i].fluxo, fluxo, 16);
                subs_temp[i].fluxo_set = 1;
                break;
            }
        }
    }
}

const char* find_fluxo_by_ip2_porta3(const char* ip2, int porta3) {
    for (int i = 0; i < subs_count; ++i) {
        if (subs_temp[i].fluxo_set) {
            for (int j = 0; j < entry_count; ++j) {
                for (int k = 0; k < entries[j].count; ++k) {
                    if (strcmp(entries[j].ip2s[k], ip2) == 0 && entries[j].porta3s[k] == porta3) {
                        return subs_temp[i].fluxo;
                    }
                }
            }
        }
    }
    return "";
}

void write_to_file() {
    FILE *f = fopen(OUTPUT_FILE, "w");
    if (!f) {
        perror("Erro ao abrir arquivo de saída");
        return;
    }

    for (int i = 0; i < entry_count; ++i) {
	//fprintf(f, "%s %s %s %d %s %d =>", PREFIX, entries[i].fluxo, entries[i].ip1, entries[i].porta1, FIXED_IP, entries[i].porta2);
	
	fprintf(f, "%s %s %d %s %d =>", PREFIX, entries[i].ip1, entries[i].porta1, FIXED_IP, entries[i].porta2);
        for (int j = 0; j < MAX_OUTPUT_IPS; ++j) {
            if (j < entries[i].count) {
                fprintf(f, " %s %d %s", entries[i].ip2s[j], entries[i].porta3s[j], entries[i].macs[j]);
            } else {
                fprintf(f, " 0.0.0.0 0 00:00:00:00:00:00");
            }
        }
        fprintf(f, "\n");
    }

    fclose(f);
}

void remove_entry_by_porta2(int porta2) {
    for (int i = 0; i < entry_count; ++i) {
        if (entries[i].porta2 == porta2) {
            for (int j = i; j < entry_count - 1; ++j)
                entries[j] = entries[j + 1];
            entry_count--;
            write_to_file();
            break;
        }
    }
}

void handle_fluxo_temp(const char *line) {
    int thread_id;
    char fluxo[17], ip1[32];

    if (sscanf(line, "%d : main_publisher : %16s conectou; %31[^:]:", &thread_id, fluxo, ip1) == 3) {
	
	printf("Publisher -> Thread: %d --- Fluxo: %s --- IP: %s\n", thread_id, fluxo, ip1);

        for (int i = 0; i < fluxos_count; ++i) {
            if (fluxos_temp[i].thread_id == thread_id) return;  // já existe
        }
        FluxoTemp ft;
        ft.thread_id = thread_id;
        strncpy(ft.fluxo, fluxo, 16);
        strncpy(ft.ip1, ip1, 31);
        fluxos_temp[fluxos_count++] = ft;
    }
}

void handle_porta_alloc(const char *line) {
    int thread_id, porta2;
    if (sscanf(line, "1 : thread_mesa_mensagens : %d solicitou um canal de dados... alocada a porta %d", &thread_id, &porta2) == 2) {
	printf("Publisher -> Thread: %d --- Porta: %d\n", thread_id, porta2);
        for (int i = 0; i < fluxos_count; ++i) {
            if (fluxos_temp[i].thread_id == thread_id) {
                // Só atualiza a info temporária, não cria entrada ainda
                // Armazena a porta2 associada ao fluxo
                for (int j = 0; j < entry_count; ++j) {
                    if (strcmp(entries[j].ip1, fluxos_temp[i].ip1) == 0 && entries[j].porta2 == 0) {
                        entries[j].porta2 = porta2;
                        strncpy(entries[j].fluxo, fluxos_temp[i].fluxo, 16);
                        return;
                    }
                }

                // Não cria entrada ainda; será criada quando linha real chegar com porta1
                return;
            }
        }
    }
}

void handle_thread_liberation(const char *line) {
    int thread_id;
    if (sscanf(line, "1 : liberarRecursosFilho : liberando recursos de %d", &thread_id) == 1) {
	
	    printf("Liberando recursos da thread %d\n", thread_id);

        for (int i = 0; i < subs_count; ++i) {
		printf("Sub Thr ID: %d --- Sub Flux: %d\n", subs_temp[i].thread_id, subs_temp[i].fluxo_set);
            if (subs_temp[i].thread_id == thread_id && subs_temp[i].fluxo_set) {
                const char *fluxo = subs_temp[i].fluxo;
                const char *ip2 = subs_temp[i].ip2;

                // Procura a entrada do fluxo
                for (int j = 0; j < entry_count; ++j) {
                    if (strcmp(entries[j].fluxo, fluxo) == 0) {
                        // Remove subscriber com IP2 correspondente
                        for (int k = 0; k < entries[j].count; ++k) {
                            if (strcmp(entries[j].ip2s[k], ip2) == 0 && entries[j].porta3s[k] == subs_temp[i].porta3) {
                                // Remover deslocando os elementos à esquerda
                                for (int m = k; m < entries[j].count - 1; ++m) {
                                    strncpy(entries[j].ip2s[m], entries[j].ip2s[m + 1], 31);
                                    entries[j].porta3s[m] = entries[j].porta3s[m + 1];
                                    strncpy(entries[j].macs[m], entries[j].macs[m + 1], 17);
                                }
                                // Limpa o último campo
                                strncpy(entries[j].ip2s[entries[j].count - 1], "0.0.0.0", 31);
                                entries[j].porta3s[entries[j].count - 1] = 0;
                                strncpy(entries[j].macs[entries[j].count - 1], "00:00:00:00:00:00", 17);

                                entries[j].count--;  // reduz total de subscribers
                                break;
                            }
                        }
                        break;
                    }
                }

                // Remove da lista temporária
                for (int m = i; m < subs_count - 1; ++m) {
                    subs_temp[m] = subs_temp[m + 1];
                }
                subs_count--;
		write_to_file();
                break;
            }
        }
    }
}

int main() {
    FILE *fp = popen(CMD, "r");
    if (!fp) {
        perror("Erro ao executar docker logs");
        return 1;
    }

    char line[MAX_LINE];
    while (fgets(line, sizeof(line), fp)) {
	if (strstr(line, "liberando recursos de")) {
	    trim_newline(line);
 	    handle_thread_liberation(line);
	    continue;
	}

	if (strstr(line, "Subscriber conectou;")) {
	    handle_subscriber_connection(line);
	    continue;
	}

	if (strstr(line, "Fazendo proxy do")) {
	    handle_proxy_info(line);
	    continue;
	} 
	// 1. Verifica log de conexão de fluxo
        if (strstr(line, "conectou;")) {
            handle_fluxo_temp(line);
            continue;
        }

        // 2. Verifica log de alocação de porta
        if (strstr(line, "solicitou um canal de dados")) {
            handle_porta_alloc(line);
            continue;
        }

        // 3. Verifica liberação de porta
        if (strstr(line, "liberando a porta")) {
            int porta;
            if (sscanf(line, "1 : liberarRecursosFilho : liberando a porta %d", &porta) == 1) {
                remove_entry_by_porta2(porta);
            }
            continue;
        }

        // 4. Verifica linha padrão de conexão
        char ip1[32], ip2[32];
        int porta1, porta2, porta3;
        
	if (sscanf(line, "%31s %d %d => %31s %d", ip1, &porta1, &porta2, ip2, &porta3) == 5) {
            int idx = match_entry(ip1, porta1, porta2);
            const char *fluxo = "";

	    for (int i = 0; i < subs_count; ++i) {
		    if (subs_temp[i].porta_set != 1) {
			    subs_temp[i].porta_set = true;
			    subs_temp[i].porta3 = porta3;
			    break;
		    } else {
			    continue;
		    }
	    }

	    for (int i = 0; i < fluxos_count; ++i) {
		if (fluxos_temp[i].porta_set != 1) {
			fluxos_temp[i].porta_set = true;
			fluxos_temp[i].porta1 = porta1;
			break;
		} else {
			continue;
		}
            }

	    if (porta1 == 0)
		continue;

	    	print_all_publishers();
		print_all_subscribers();

            if (idx == -1) {
                if (entry_count >= MAX_ENTRIES) continue;
                LogEntry *e = &entries[entry_count++];
                strcpy(e->ip1, ip1);
                e->porta1 = porta1;
                e->porta2 = porta2;
                strcpy(e->ip2s[0], ip2);
                e->porta3s[0] = porta3;
                get_mac_from_ip(ip2, e->macs[0]);
                e->count = 1;

                fluxo = find_fluxo_by_ip_porta2(ip1, porta2);
                strncpy(e->fluxo, fluxo, 16);

		if (strlen(e->fluxo) == 0) {
 			fluxo = find_fluxo_by_ip2_porta3(ip2, porta3);
			 strncpy(e->fluxo, fluxo, 16);
		}
            } else {
                LogEntry *e = &entries[idx];
                fluxo = e->fluxo;
                int exists = 0;
                for (int j = 0; j < e->count; ++j) {
                    if (strcmp(e->ip2s[j], ip2) == 0 && e->porta3s[j] == porta3) {
                        exists = 1;
                        break;
                    }
                }
                if (!exists && e->count < MAX_OUTPUT_IPS) {
                    strcpy(e->ip2s[e->count], ip2);
                    e->porta3s[e->count] = porta3;
                    get_mac_from_ip(ip2, e->macs[e->count]);
                    e->count++;
                }
            }
            write_to_file();
        }
    }

    pclose(fp);
    return 0;
}

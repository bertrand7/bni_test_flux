/**
 * Copyright (c) 2022, Bertrand NICAISE.
 * 
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 * 
 * Source: http://opensource.org/licenses/ISC
 *  
 **/
/**
 * TODO : utiliser les fonction sécurisées pour strncpy
 */
#define _GNU_SOURCE
#include <sys/wait.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>

/* Partie nécessaire pour les sockets */
#ifdef _WIN32
#else
#define INVALID_SOCKET -1
typedef int SOCKET;
#endif
#include <errno.h>
#include <sys/socket.h>  // socket
#include <sys/types.h>   // send
#include <netinet/in.h>  // sockaddr_in, IPPROTO_TCP
#include <arpa/inet.h>   // hton*, ntoh*, inet_addr
#include <netdb.h>	 //

#define MAX_PID_LEN 30
#define IP_STR_MAX_SIZE 20
#define DOMAINE_STR_MAX_SIZE 512
#define MAX_ALLOWED_LINE_SIZE 2048
#define PATH_MAX_LENGTH 255
#define BLOC_SIZE 256;
#define DEFAULT_INPUT_PATH "connextions.ip"
#define DEFAULT_OUTPUT_PATH "connextions_result.dat"
#define DEFAULT_MS_TIMEOUT 2000

/* flag pour verbose */
static int verbose_flag;
static bool VERBOSE = false;
static unsigned long TIMEOUT_USECONDS = DEFAULT_MS_TIMEOUT * 1000;
static char OUTPUT_PATH[PATH_MAX_LENGTH + 1] = DEFAULT_OUTPUT_PATH;
static char INPUT_PATH[PATH_MAX_LENGTH + 1] = DEFAULT_INPUT_PATH;
struct s_connexion {
	char original[DOMAINE_STR_MAX_SIZE +1];
	char ip[IP_STR_MAX_SIZE + 1];
	char fqdn[DOMAINE_STR_MAX_SIZE +1];
	char domaine[DOMAINE_STR_MAX_SIZE + 1];
	unsigned int port;
};
typedef struct s_connexion t_connexion;

typedef struct s_options {
	int timeout;
	char input_path[PATH_MAX_LENGTH + 1];
	char output_path[PATH_MAX_LENGTH + 1];
} t_options;


/* fonctions spécifiques */
void process_args (int argc, char *** argv_ptr, t_options* options) ;
void show_info (const char* processus_name, int pid, int ppid, int fpid);
void iniResult () ;
void fill_ip (char *file_line, t_connexion* ip) ;
int count_lines () ;
void writeResult (char *result_str) ;
void processus_to_watch (char *who, t_connexion *cnx, int no_cnx, int total_cnx) ;
void processu_pere (char * who, int pid_to_kill) ;
void wait_and_kill (char *who, int pid_to_kill, t_connexion *cnx, int no_cnx, int total_cnx) ;
void usage() ;
/* fonctions de lib */
bool bni_is_tcp_connectable (const char* ip, unsigned int port, bool verbose);
int bni_get_domain_ip (const char* ip);
const char* bni_get_first_ip_from_fqdn (const char* fqdn, char* ip, int ip_length, int domain) ;
const char * bni_get_fqdn (const char* ip, char* fqdn, int fqdn_max_length);


int main(int argc, char** argv) {

	int pid, kpid, nb_cnx = 4;
	int oppid = getppid();
	t_connexion ip;
	char* line;

	/* varivale de manipulation du fichier */
	char* filename = INPUT_PATH;
	size_t read_size = 0;
	ssize_t nb_char_read = 0;
	int nb_lignes = 0;
	int i = 0;

	/* gestion des options entrées par l'utilistateur. */
	t_options options = { .timeout = DEFAULT_MS_TIMEOUT, .input_path = DEFAULT_INPUT_PATH, .output_path = DEFAULT_OUTPUT_PATH };
	process_args (argc, &argv, &options) ;
	TIMEOUT_USECONDS = options.timeout * 1000;
	strncpy(INPUT_PATH, options.input_path, PATH_MAX_LENGTH +1);
	strncpy(OUTPUT_PATH, options.output_path, PATH_MAX_LENGTH +1);

	if (VERBOSE) { printf ("timeout = %d ms, input-path = '%s', output-path = '%s'\n", options.timeout, options.input_path, options.output_path); }


	iniResult();
	nb_cnx = count_lines();
	printf ("nombre de connexion à tester : %d\n", nb_cnx);
	
	pid = 1;

	FILE* df = fopen(filename, "r");

	if (df == NULL) {
		fprintf(stderr, "impossible d'ouvrir '%s'\n", filename);
		exit(EXIT_FAILURE);
	}
	if (VERBOSE) { printf("fichier '%s' est ouvert.\n", filename); }

	// sans le test sur le volume, le programme reprendrait au début sans s'arréter.
	while (i < nb_cnx && (nb_char_read = getline(&line, &read_size, df)) != -1 ) {
		i++;
		if (VERBOSE) { printf ("%d:%zd:%zd\t >%s</>", nb_lignes + 1, nb_char_read, read_size, line); }

		fill_ip (line, &ip );
		if (VERBOSE) { printf ( "%s --> %d \n", ip.ip, ip.port); }
		pid = fork();

		if (VERBOSE) { printf ("-------------------------> %d, cnx = %s:%d, pid = %d, ppid = %d, oppid = %d\n", i, ip.ip, ip.port, getpid(), getppid(), oppid); }

		switch (pid) {
			case -1 : printf("Erreur\n");
				return EXIT_FAILURE;
			case 0 : show_info("fils", getpid(), getppid(), pid);
				processus_to_watch("fils", &ip, i, nb_cnx);
				return EXIT_SUCCESS;
			default : show_info("père", getpid(), getppid(), pid);
				kpid = fork();
				if (kpid == 0) {
				      show_info("stimeout", getpid(), getppid(), pid);
				      wait_and_kill("stimeout", pid, &ip, i, nb_cnx);
				      return EXIT_SUCCESS;
				} else {
					waitpid(pid, 0, WSTOPPED);
					processu_pere("père", kpid);
				}
				break;
		}
	}

	free (line);
	fclose(df);
	if (VERBOSE) { printf("fichier '%s' est fermé.\n", filename); }
	return EXIT_SUCCESS;
}

void show_info (const char* processus_name, int pid, int ppid, int fpid) {
	if (VERBOSE) { printf("Processus %s : pid = %d\tppid = %d\tfork_id = %d\n",processus_name, pid, ppid, fpid); }
}
// En attendant de faire de la mémoire partagée :
void iniResult (char* output_path) {
	FILE * fd_result_file;
	char * result_file = OUTPUT_PATH;
	
	fd_result_file = fopen (result_file, "w");
	if (fd_result_file == NULL) {
		fprintf(stderr, "Impossible d'ouvrire le fichier de  résultat '%s'\n", result_file);
		return; 
	}
	fclose(fd_result_file);
}

void fill_ip (char *file_line, t_connexion* ip) {
	char delim[] = " ";
	char *ptr;
	int domain;
	char fqdn [DOMAINE_STR_MAX_SIZE + 1];
	char ip_str [IP_STR_MAX_SIZE + 1];
	ptr = strtok(file_line, delim);
	if (ptr != NULL) {
		
		strncpy(ip->original, ptr, DOMAINE_STR_MAX_SIZE);
		*(ip->original + sizeof(ip->original) -1) = '\0';
		domain = bni_get_domain_ip (ptr);
		switch (domain) {
			case AF_INET6:
				bni_get_fqdn(ptr, fqdn, sizeof(fqdn));
				bni_get_first_ip_from_fqdn(fqdn, ip_str, sizeof(ip_str), AF_INET);
				strncpy(ip->ip, ip_str, IP_STR_MAX_SIZE);
				*(ip->ip + sizeof(ip->ip) -1) = '\0';
				strncpy(ip->fqdn, fqdn, DOMAINE_STR_MAX_SIZE);

				break;
			case AF_INET:
				bni_get_fqdn(ptr, fqdn, sizeof(fqdn));
				strncpy(ip->ip, ptr, IP_STR_MAX_SIZE);
				*(ip->ip + sizeof(ip->ip) -1) = '\0';
				strncpy(ip->fqdn, fqdn, DOMAINE_STR_MAX_SIZE);
				break;
			default:
				bni_get_first_ip_from_fqdn (ptr, ip_str, sizeof(ip_str), AF_INET);
				strncpy(ip->ip, ip_str, IP_STR_MAX_SIZE);
				strncpy(ip->fqdn, ptr, DOMAINE_STR_MAX_SIZE);
				*(ip->fqdn + sizeof(ip->fqdn) -1) = '\0';
		}
		ptr = strtok(NULL, delim);
		if (ptr != NULL) {
			//ip->port = atoi(ptr);
			ip->port = (int) strtol(ptr, NULL, 10);
			ptr = strtok(NULL, delim);
			if (ptr != NULL) {
				*(ptr + strcspn(ptr, "\r\n")) = 0;
				strncpy(ip->domaine, ptr, DOMAINE_STR_MAX_SIZE);
			} else {
				strcpy(ip->domaine, "not specified");
			}
		}
	}
	//TODO// ip->ip = NULL;
	
}

int count_lines () {
	char* line;

	char* filename = INPUT_PATH;
	size_t read_size = 0;
	ssize_t nb_char_read = 0;
	int lines_number = 0;

	FILE* df = fopen(filename, "r");

	if (df == NULL) {
		fprintf(stderr, "impossible d'ouvrir '%s'\n", filename);
		exit(EXIT_FAILURE);
	}
	if (VERBOSE) { printf("fichier '%s' est ouvert pour comptage.\n", filename); }

	while ((nb_char_read = getline(&line, &read_size, df)) != -1) {
		lines_number++;
	}


	free (line);
	fclose(df);
	if (VERBOSE) { printf("fichier '%s' est fermé.\n", filename); }
	return lines_number;
}

void process_args (int argc, char *** argv_ptr, t_options* options) {
	char** argv = *(argv_ptr);
	int c;
	while (1) {
		static struct option long_options[] = {
			/* options qui placent un flag */
			{ "verbose", no_argument, &verbose_flag, 1},
			{ "breif"  , no_argument, &verbose_flag, 0},
			/* options qui ne placent pas de flag */
			{ "help"        , no_argument      , 0, 'h' },
			{ "timeout"     , required_argument, 0, 't' },
			{ "input-path"  , required_argument, 0, 'i' },
			{ "output-path" , required_argument, 0, 'o' },
			/* pour avoir uniquement des lignes avec , */
			{ 0, 0, 0, 0 } 
		};

		/* variable dans laquelle getopt_long stoque les index des options. */
		int option_index = 0;

		c = getopt_long (argc, argv, "ht:i:o:"
				, long_options, &option_index);

		/* Détection de la fin des options */
		if (c == -1) {
			break;
		}

		switch (c) {
			/* cas des options avec flags */
			case 0:
				if (long_options[option_index].flag != 0) {
					break;
				}
				printf ("option %s", long_options[option_index].name);
				if (optarg) {
					printf (" avec argument %s", optarg);
				}
				printf ("\n");
				break;

			case 'h':
				usage ();
				exit( EXIT_SUCCESS );
				break;

			case 't':
				options->timeout = (int) strtol(optarg, NULL, 10); //atoi (optarg);
				break;

			case 'i':
				strncpy (options->input_path, optarg, PATH_MAX_LENGTH);
				break;

			case 'o':
				strncpy (options->output_path, optarg, PATH_MAX_LENGTH);
				break;

			case '?':
				/* getopt_long a déjà affiché un message d'erreur. */
				break;
			default:
				abort();
		}
	}

	if (verbose_flag) {
		VERBOSE = true;
		puts ("Le flag verbose est positionné\n");
	}
	
	/* on affiche les arguments restants */
	if (optind < argc) {
		puts ("Arguments hors options :");
		while (optind < argc) {
			printf ("%s\t", argv[optind]);
			putchar('\n');
			optind++;
		}
	}
}

void usage() {
	char default_in[] = DEFAULT_INPUT_PATH;
	char default_out[] = DEFAULT_OUTPUT_PATH;
	puts("Usage : flux_test [options]                                              ");
	puts("                                                                         ");
	printf(" Teste les connexions définies dans le fichier : '%s'\n", DEFAULT_INPUT_PATH);
	puts(" ou celui indiqué par l'otption (-i ou --input-path)                     ");
	printf(" et écrit le résultat dans le fichier '%s'\n", DEFAULT_OUTPUT_PATH);
	puts(" ou celui indiqué par l'options (-o ou --output-path)                    ");
	printf(" Le timeout par défaut est de %d millisecondes\n", DEFAULT_MS_TIMEOUT);
	puts("---------                                                                ");
	puts("Options :                                                                ");
	puts("                                                                         ");
	puts(" -h --help            affiche l'aide.                                    ");
	puts("                                                                         ");
	puts(" -t --timeout         Timeout en millisecondes.                          ");
	puts("                                                                         ");
	puts(" -i --input-path      Fichier d'ip avec le format suitant                ");
	puts("                                                                         ");
	printf("                      Chemin par défaut : '%s'\n", default_in);
	puts("                      Format :                                           ");
	puts("                       <ip/fqdn> <no-port> <description>                 ");
	puts("                      Exemple:                                           ");
	puts("                      192.168.1.1 2783 livbox                            ");
	puts("                                                                         ");
	puts(" -o --output-path     Fichier dans lequel sont stoqués les résultats.    ");
	printf("                      Chemin par défaut : '%s'\n", default_out);
	puts("                      Format :                                           ");
	puts("                      <fileentry>:<ip>:<port>:<fqdn>:<description>:<ok|ko|to>");
	puts("                      filentry est ce qui a été placé dans le fichier d'input");
	puts("                      ok : la connexion répond correctement.             ");
	puts("                      ko : la connexion répond avec une erreur.          ");
	puts("                      to : la connexion ne réponds pas dans le temps     ");
	puts("                           défini par le timeout.                        ");
	puts("                                                                         ");

}

void writeResult (char *result_str) {
	FILE * fd_result_file;
	char * result_file = OUTPUT_PATH;
	
	fd_result_file = fopen (result_file, "a");
	if (fd_result_file == NULL) {
		fprintf(stderr, "Impossible d'ouvrire le fichier de  résultat '%s'\n", result_file);
		return; 
	}
	fprintf (fd_result_file, result_str);
	fclose(fd_result_file);
}


void processus_to_watch (char *who, t_connexion *cnx, int no_cnx, int total_cnx) {
	int retour;
	char result_str[MAX_ALLOWED_LINE_SIZE + 1];

	if (VERBOSE) { printf ("%s\t=> work start \n", who); }
	retour = bni_is_tcp_connectable (cnx->ip, cnx->port, VERBOSE);
	printf ("%s(%d)\t=> work finished\t|%5d/%5d| %s:%d\t\t%s(%s)\t => %s\n", who, getpid(), no_cnx, total_cnx, cnx->ip, cnx->port, cnx->fqdn, cnx->domaine, retour == 1 ? "ok":"ko");
	snprintf (result_str, MAX_ALLOWED_LINE_SIZE, "%s:%s:%d:%s:%s:%s\n", cnx->original, cnx->ip, cnx->port, cnx->fqdn, cnx->domaine, retour == 1 ? "ok":"ko");
	writeResult(result_str);
}


void processu_pere (char * who, int pid_to_kill) {

	if (VERBOSE) { printf ("%s(%d)\t=> end => kill pid = %d\n", who, getpid(), pid_to_kill); }
	kill(pid_to_kill, SIGKILL);
}

void wait_and_kill (char *who, int pid_to_kill, t_connexion *cnx, int no_cnx, int total_cnx) {
	int kill_success;
	char result_str[MAX_ALLOWED_LINE_SIZE + 1];
	if(VERBOSE) { printf ("%s (%d)\t=> wait => pid to kill = %d\n", who, getpid(), pid_to_kill); }
	usleep(TIMEOUT_USECONDS);
	printf ("%s(%d)\t=> work finished\t|%5d/%5d| %s:%d\t\t%s(%s)\t=> to\n", who, getpid(), no_cnx, total_cnx, cnx->ip, cnx->port, cnx->fqdn, cnx->domaine);
	kill_success = kill(pid_to_kill, SIGKILL);
	snprintf (result_str, MAX_ALLOWED_LINE_SIZE, "%s:%s:%d:%s:%s:to\n", cnx->original, cnx->ip, cnx->port, cnx->fqdn, cnx->domaine);
	writeResult(result_str);
	if (VERBOSE) {
		printf ("%s(%d)\t=> killed pid => %d\tkill_value => %d\n", who, getpid(), pid_to_kill, kill_success);
	}
}

/* FONCTIONS DE LIB */



bool bni_is_tcp_connectable (const char* ip, unsigned int port, bool verbose) {
	char * exit_str="0x1dclose0x0d";  // Séquence pour la sortie des serveurs http.
	
	if (verbose) { printf("connexion à %s:%d ...\n",ip, port); }
	SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET) {
		fprintf(stderr, "Impossible de créer la socket");
		return false;
	}
	
	

	struct sockaddr_in server;
	server.sin_addr.s_addr = inet_addr(ip);
	server.sin_family = AF_INET;
	server.sin_port = htons(port);

	int connect_answer = connect(s, (struct sockaddr *) &server, sizeof( server));
	if ( connect_answer != 0) {
		if (verbose) { fprintf(stderr, "Impossible de se connecter : %d\n", connect_answer); }
		return false;
	}

	if (verbose) { printf("Connecté au serveur\n"); }
	send (s, exit_str, strlen(exit_str), 0);

	return true;
}

const char* bni_get_first_ip_from_fqdn (const char* fqdn, char* ip, int ip_length, int domain) {
	struct addrinfo hints;
	struct addrinfo *results, *p;
	struct sockaddr_in *ip_socket;
	struct sockaddr_in6 *ip6_socket;
	int status;
	char *hostname;
	// char ip[MAX_IP_LENGTH + 1];
	char addr[INET_ADDRSTRLEN + 1];
	char addr6[INET6_ADDRSTRLEN + 1];

	memset (&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ( (status = getaddrinfo (fqdn, NULL, &hints, &results)) != 0) {
		if (VERBOSE) fprintf (stderr, "getaddrinfo: %s\n", gai_strerror(status) );
		strncpy ("", ip, ip_length);
		return "";
	}

	for (p = results; p != NULL; p = p->ai_next) {
		if (p->ai_family == AF_INET6) {
			if (domain != AF_INET6) {
				continue;
			}
			ip6_socket = (struct sockaddr_in6 *) p->ai_addr;
			inet_ntop( AF_INET6, ip6_socket, addr6, INET6_ADDRSTRLEN );
			strncpy (ip, addr6, ip_length);
			return ip;
		} else {
			if (domain != AF_INET) {
				continue;
			}
			memset (&addr, 0, sizeof(addr));
			ip_socket = (struct sockaddr_in *) p->ai_addr;
			inet_ntop( AF_INET, &ip_socket->sin_addr, addr, INET_ADDRSTRLEN );

			strncpy (ip, addr, ip_length);
			return ip;
		}
	}

	freeaddrinfo (results);

	return "";
}

int bni_get_domain_ip (const char* ip) {
	char scan[INET6_ADDRSTRLEN + 1] = "";
	sscanf(ip, "%[0-9.]s", scan);
	if (strlen(scan) != strlen(ip)) {
		sscanf(ip, "%[0-9a-f:]", scan);
		if (strlen(scan) != strlen(ip)) {
			if (VERBOSE) fprintf (stderr, "L'ip (%s) renseignées n'est ni de l'ipv4 ne de l'ipv6\n", ip);
			return 0;
		} else {
			return AF_INET6;
		}
	} else {
		return AF_INET;
	}
	return 0;
}

const char* bni_get_fqdn (const char* ip, char* fqdn, int fqdn_max_length) {
	struct sockaddr_in ip_socket;
	struct sockaddr_in6 ip6_socket;
	int gni_err = 0;


	switch (bni_get_domain_ip(ip)) {
		case AF_INET:
			memset (&ip_socket, 0, sizeof(ip_socket));
			ip_socket.sin_family = AF_INET;
			if (inet_pton (AF_INET, ip, &ip_socket.sin_addr) < 0) {
				if (VERBOSE) fprintf (stderr, "problème de conversion du fqdn au format réseau\n");
				return "";
			}
			if (getnameinfo((struct sockaddr*)&ip_socket, sizeof(ip_socket), fqdn, fqdn_max_length, NULL, 0, NI_NAMEREQD)) {
				if (VERBOSE) fprintf (stderr, "Impossible de trouver le fqdn corremspondant à %s\n", ip);
				return "";
			}
			break;
		case AF_INET6:
			memset (&ip6_socket, 0, sizeof(ip6_socket));
			ip6_socket.sin6_family = AF_INET6;
			if (inet_pton (AF_INET6, ip, &ip6_socket.sin6_addr) < 0) {
				if (VERBOSE) fprintf (stderr, "problème de conversion du fqdn au format réseau\n");
				return "";
			}
			if ((gni_err = getnameinfo((struct sockaddr*)&ip6_socket, sizeof(ip6_socket), fqdn, fqdn_max_length, NULL, 0, NI_NAMEREQD))) {
				if (VERBOSE) fprintf (stderr, "Impossible de trouver le fqdn corremspondant à %s\n", ip);
				// show_error(gni_err);
				return "";
			}
			break;
		default:
			if (VERBOSE) fprintf (stderr, "Le programme ne check que les ipv4 et ipv6\n");
			return "";

	}
	
	return fqdn;
}

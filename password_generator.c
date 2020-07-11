/* Password wallet */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <openssl/sha.h> // add SHA256 function
#include <errno.h>

#define LIGNE_MAX 5
#define HASH_SIZE 32
#define HASH_HEX_SIZE 65

#ifndef SHA256_DIGEST_LENGTH
#define SHA256_DIGEST_LENGTH    32
#endif
#define PASSWORD_LENGTH 19 //16 characters and 3 "-"

typedef struct 
{
	char name[50];
	char login[50];
	char password[PASSWORD_LENGTH];
	int cipher[PASSWORD_LENGTH];
	char hash[PASSWORD_LENGTH];
}account_t;

void erreur_IO ( const char *message ) {
  perror (message);
  exit (EXIT_FAILURE);
}

int tempo(int n)
{
	int a = 0;
	for (int i = 0; i < n; i++)
	{
		a++;
	}
	return a;
}

void password_generator(char p[PASSWORD_LENGTH])
{
	int c; //int in ascii table of the new char
	float p_maj = 0.1; //probability that c will be in MAJ (if it's a letter)
	float a; // 0<=a<=1
	srand(time(NULL));   // Initialization, should only be called once.
	FILE* fpasswords; 	

	for (int i = 0; i< PASSWORD_LENGTH; i++)
	{
		c = 60;
		while(c>57 && c <97)
		{
			c = rand()%75;	// so that c is a number or 
			c += 48;		// a min letter in ascii table
		}
		if (c > 96)
		{
			a = (rand()+1.0)/(RAND_MAX+1.0);
			if (a < p_maj)
				c -= 32; //change c in MAJ
		}
		p[i] = c;
	}
	for(int j = 4; j<19; j+=5)
		p[j] = 45; // puts "-"
	p[PASSWORD_LENGTH] = '\0';
}

void hashToString(char *output, const unsigned char *hash)
{
	char buffer[3];
	char hex_hash[HASH_HEX_SIZE] = {0};

	for(int i = 0; i < HASH_SIZE; i++)
	{
		memset(buffer, 0, sizeof(buffer));
		sprintf(buffer,"%02x", hash[i]);
		strcat(hex_hash, buffer);
	}

	strcpy(output,hex_hash);

	output[HASH_HEX_SIZE] = 0;
}

/* return 1 if the attempt is the password, otherwise 0 */
int checkPassword(unsigned char *attempt)
{
  	tempo(4000);
	char *sHashPassword = "e1b9005b2bd9380bf2ad43494b6a0c3de7db20532a7297fde352214e9610e4b7"; //2536
	unsigned char *hashAttempt = SHA256(attempt, strlen(attempt), 0);
	char sHashAttempt[HASH_HEX_SIZE];
	hashToString(sHashAttempt, hashAttempt);

	if (strncmp(sHashAttempt, sHashPassword, HASH_HEX_SIZE) == 0)
	{
		return 1;
	}
	/*for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
		printf("%02x", hashAttempt[i]);
	putchar('\n'); */
	printf("p %s\na %s\n", sHashPassword, sHashAttempt);
  return 0;
}

void createHash(char *passwordAttempt, int once, unsigned char* hash)
{
	int l = strlen(passwordAttempt);
	unsigned char attemptp[l + 1];
	char sOnce[2];
	sprintf(sOnce, "%d", once);
	strcpy(attemptp, passwordAttempt);
	strcat(attemptp, sOnce);
	hashToString(hash, SHA256(attemptp, l+1, 0));
}

int hexToBinary(char c)
{
	char res[4];
	switch(c)
	{
		case '0':
			res[0] = '0';
			res[1] = '0';
			res[2] = '0';
			res[3] = '0';
			break;
		case '1':
			res[0] = '0';
			res[1] = '0';
			res[2] = '0';
			res[3] = '1';
			break;
		case '2':
			res[0] = '0';
			res[1] = '0';
			res[2] = '1';
			res[3] = '0';
			break;
		case '3':
			res[0] = '0';
			res[1] = '0';
			res[2] = '1';
			res[3] = '1';
			break;
		case '4':
			res[0] = '0';
			res[1] = '1';
			res[2] = '0';
			res[3] = '0';
			break;
		case '5':
			res[0] = '0';
			res[1] = '1';
			res[2] = '0';
			res[3] = '1';
			break;
		case '6':
			res[0] = '0';
			res[1] = '1';
			res[2] = '1';
			res[3] = '0';
			break;
		case '7':
			res[0] = '0';
			res[1] = '1';
			res[2] = '1';
			res[3] = '1';
			break;
		case '8':
			res[0] = '1';
			res[1] = '0';
			res[2] = '0';
			res[3] = '0';
			break;
		case '9':
			res[0] = '1';
			res[1] = '0';
			res[2] = '0';
			res[3] = '1';
			break;
		case 'a':
			res[0] = '1';
			res[1] = '0';
			res[2] = '1';
			res[3] = '0';
			break;
		case 'b':
			res[0] = '1';
			res[1] = '0';
			res[2] = '1';
			res[3] = '1';
			break;
		case 'c':
			res[0] = '1';
			res[1] = '1';
			res[2] = '0';
			res[3] = '0';
			break;
		case 'd':
			res[0] = '1';
			res[1] = '1';
			res[2] = '0';
			res[3] = '1';
			break;
		case 'e':
			res[0] = '1';
			res[1] = '1';
			res[2] = '1';
			res[3] = '0';
			break;
		case 'f':
			res[0] = '1';
			res[1] = '1';
			res[2] = '1';
			res[3] = '1';
			break;
		case '\0':
			res[0] = '\0';
			break;
	}
	int a=0;
	for (int i = 0; i<4; i++)
	{
		a += (int) res[i];
		a *= 2;
	}

	return a;
}

void xorEncryption(char hash[HASH_HEX_SIZE], char password[PASSWORD_LENGTH], int cipher[PASSWORD_LENGTH])
{
	int hexi;
	for (int i = 0; i < PASSWORD_LENGTH; i++)
	{
		hexi = hexToBinary(hash[i]);
		cipher[i] = hexi ^ password[i];
	}
}

void xorDecryption(char hash[HASH_HEX_SIZE], char password[PASSWORD_LENGTH], int cipher[PASSWORD_LENGTH])
{
	int hexi;
	for (int i = 0; i < PASSWORD_LENGTH; i++)
	{
		hexi = hexToBinary(hash[i]);
		password[i] = hexi ^ cipher[i];
	}
}

void fprintAccount(account_t a)
{
	FILE* fpasswords;
	fpasswords = fopen("passwords.txt", "a");
	fprintf(fpasswords, "%s %s ", a.name, a.login);
	for (int i = 0; i < PASSWORD_LENGTH; i++)
	{
		fprintf(fpasswords, "%d ", a.cipher[i]);
	}
	fprintf(fpasswords, "\n");
	fclose(fpasswords);
}

void printAccount(account_t a)
{
	printf("Nom : %s\nLogin : %s\nPassword : %s\n", a.name, a.login, a.password);
	for (int i = 0; i < PASSWORD_LENGTH; i++)
	{
		printf("%d ", a.cipher[i]);
	}
	printf("\nHash : %s", a.hash);
}


int main(void)
{
// VAR INIT
  	char passwordAttempt[5];
	account_t a;
	FILE* fpasswords;
	account_t taba[34];

// LOGIN
	printf("Password : ");
	scanf("%s", passwordAttempt);

	if (checkPassword(passwordAttempt) != 1)
	{
		return 0;
	}

	unsigned char *hashAttempt = SHA256(passwordAttempt, strlen(passwordAttempt), 0);
  	char sHashAttempt[HASH_HEX_SIZE];
  	hashToString(sHashAttempt, hashAttempt);

// LECTURES DONNES
	int flag = 0;
	int nb_passwords = -1;
	fpasswords = fopen("passwords.txt", "r");
	while(flag != -1)
	{
		memset(taba[nb_passwords].password, 0, sizeof(taba[nb_passwords].password));
		memset(taba[nb_passwords].hash, 0, sizeof(taba[nb_passwords].hash));
		nb_passwords++;
		fscanf(fpasswords, "%s %s", taba[nb_passwords].name, taba[nb_passwords].login);
		for (int i = 0; i < PASSWORD_LENGTH; i++)
		{
			flag = fscanf(fpasswords, "%d", &taba[nb_passwords].cipher[i]);
		}
	}
	unsigned char hash[SHA256_DIGEST_LENGTH];
	for (int i = 0; i < nb_passwords; i++)
	{
		createHash(passwordAttempt, i, taba[i].hash);
		xorDecryption(taba[i].hash, taba[i].password, taba[i].cipher);
	}

// MENU
	const int menuDisplayPasswords = 0;
	const int menuPasswordGeneration = 1;
	const int menuAddPassword = 2;
	const int quit = 3;
	int choice = quit+1;

	while (choice != quit)
	{
		printf("\n** MENU **\nDisplay passwords: %d\nPassword generation: %d\nAdd password: %d\nQuit: %d\n", menuDisplayPasswords, menuPasswordGeneration,menuAddPassword,quit);
		scanf("%d", &choice);
		
		switch(choice)
		{
			case 0: //menuDisplayPasswords
				for (int i = 0; i < nb_passwords; i++)
				{
					printf("name %s; login: %s; password: %s\n\n", taba[i].name, taba[i].login, taba[i].password);
				}
				break;

			case 1: //menuPasswordGeneration
			// password generator
				printf("Name : ");
				scanf("%s", taba[nb_passwords].name);
				printf("Login : ");
				scanf("%s", taba[nb_passwords].login);
				password_generator(taba[nb_passwords].password);
				createHash(passwordAttempt, nb_passwords, taba[nb_passwords].hash);
				xorEncryption(taba[nb_passwords].hash,taba[nb_passwords].password, taba[nb_passwords].cipher);
				// display new password
				printf("%s\n", taba[nb_passwords].password);
				// save in passwords.txt
				fprintAccount(taba[nb_passwords]);
				nb_passwords++;
				break;

			case 2: //menuAddPassword
				printf("Name : ");
				scanf("%s", taba[nb_passwords].name);
				printf("Login : ");
				scanf("%s", taba[nb_passwords].login);
				printf("Password : ");
				scanf("%s", taba[nb_passwords].password);
				createHash(passwordAttempt, nb_passwords, taba[nb_passwords].hash);
				xorEncryption(taba[nb_passwords].hash,taba[nb_passwords].password, taba[nb_passwords].cipher);
				fprintAccount(a);
				nb_passwords++;
				break;

			case 3: //quit
				return 0;
		}
	}
	return 0;
}
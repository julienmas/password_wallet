// Générateur de mot de passe robustes
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
	tempo(300000000); // to prevent a brute-force attack
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
	//printf("p %s\na %s\n", sHashPassword, sHashAttempt);
  return 0;
}

void printAccount(account_t a)
{
	FILE* fpasswords;
	fpasswords = fopen("passwords.txt", "a");
	fprintf(fpasswords, "%s %s %s\n", a.name, a.login, a.password);
	fclose(fpasswords);
	free(fpasswords);
}

int main(void)
{
// VAR INIT
  char passwordAttempt[5];
	account_t a;
	FILE* fpasswords;

// LOGIN
	printf("Password : ");
	scanf("%s", passwordAttempt);
	if (checkPassword(passwordAttempt) == 1)
	{
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
					fpasswords = fopen("passwords.txt", "r");
					while(fscanf(fpasswords, "%s %s %s", a.name, a.login, a.password) > 0)
					{
						printf("%s %s %s\n\n", a.name, a.login, a.password);
					}
					fclose(fpasswords);
					break;

				case 1: //menuPasswordGeneration
				// password generator
					printf("Name : ");
					scanf("%s", a.name);
					printf("Login : ");
					scanf("%s", a.login);

					char p[PASSWORD_LENGTH];
					password_generator(p);
					strcpy(a.password, p);
					// display new password
					for (int i=0; i<PASSWORD_LENGTH+5; i++)
						printf("%c", a.password[i]);
					putchar('\n');
					printAccount(a);
					break;

				case 2: //menuAddPassword
					printf("Name : ");
					scanf("%s", a.name);
					printf("Login : ");
					scanf("%s", a.login);
					printf("Password : ");
					scanf("%s", a.password);
					printAccount(a);
					break;

				case 3: //quit
					return 0;
			}
		}
	}
	return 0;
}
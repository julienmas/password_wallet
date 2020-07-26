/* Password wallet 
 * Author : Julien Mastrangelo
 * Created in July 2020
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <openssl/sha.h> // add SHA256 function
#include <errno.h>

#define PASSWORD_LENGTH 19 //16 characters and 3 "-" : xxxx-xxxx-xxxx-xxxx
#define NB_ACCOUNT 256
#define HASH_HEX_SIZE 65
#ifndef SHA256_DIGEST_LENGTH
#define SHA256_DIGEST_LENGTH    32
#endif

typedef struct 
{
	char name[50];
	char login[50];
	char password[PASSWORD_LENGTH];
	int cipher[PASSWORD_LENGTH];
	char hash[HASH_HEX_SIZE];
}account_t;


void erreur_IO (const char *message );
int tempo(int n);
int hexToBinary(char c);
void hashToString(char *output, const unsigned char *hash);
void fprintAccount(account_t a); // print a in passwords.txt (name, login, cipher)
void printAccount(account_t a); // print a on console
int checkPassword(unsigned char *attempt); // return 1 if the attempt is the password, otherwise 0 
void password_generator(char p[PASSWORD_LENGTH]);
void createHash(char *passwordAttempt, int nonce, unsigned char* hash); // hash = SHA256(passwordAttempt+nonce)
void xorEncryption(char hash[HASH_HEX_SIZE], char password[PASSWORD_LENGTH], int cipher[PASSWORD_LENGTH]); // cipher = hash XOR password
void xorDecryption(char hash[HASH_HEX_SIZE], char password[PASSWORD_LENGTH], int cipher[PASSWORD_LENGTH]); // password = hash XOR cipher


int main(void)
{
// VAR INIT
	account_t taba[NB_ACCOUNT];

// LOGIN
	char passwordAttempt[21];
	printf("Password : ");
	scanf("%s", passwordAttempt);

	if (checkPassword(passwordAttempt) != 1)
	{
		return 0;
	}

// READ passwords.txt and fill taba
	int flag = 0;
	int nb_passwords = -1;
	FILE* fpasswords = fopen("passwords.txt", "r");
	while(flag != -1)
	{
		nb_passwords++;
		memset(taba[nb_passwords].password, 0, sizeof(taba[nb_passwords].password));
		memset(taba[nb_passwords].hash, 0, sizeof(taba[nb_passwords].hash));
		fscanf(fpasswords, "%s %s", taba[nb_passwords].name, taba[nb_passwords].login);
		for (int i = 0; i < PASSWORD_LENGTH; i++)
		{
			flag = fscanf(fpasswords, "%d", &taba[nb_passwords].cipher[i]);
		}
	}
	fclose(fpasswords);

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
	char schoice[2];
	int choice = quit+1;
	
	while (choice != quit)
	{
		printf("\n** MENU **\nDisplay passwords: %d\nPassword generation: %d\nAdd password: %d\nQuit: %d\n", menuDisplayPasswords, menuPasswordGeneration,menuAddPassword,quit);
		scanf("%s", schoice);
		sscanf(schoice, "%d", &choice);
		
		switch(choice)
		{
			case 0: //menuDisplayPasswords
				for (int i = 0; i < nb_passwords; i++)
				{
					printf("\n%s %s %s\n", taba[i].name, taba[i].login, taba[i].password);
				}
				break;

			case 1: //menuPasswordGeneration
				printf("\nName : ");
				scanf("%s", taba[nb_passwords].name);
				printf("Login : ");
				scanf("%s", taba[nb_passwords].login);
				password_generator(taba[nb_passwords].password);
				createHash(passwordAttempt, nb_passwords, taba[nb_passwords].hash);
				xorEncryption(taba[nb_passwords].hash,taba[nb_passwords].password, taba[nb_passwords].cipher);
				printf("Robust password : %s\n", taba[nb_passwords].password);	// display new password
				fprintAccount(taba[nb_passwords]);	// save it in passwords.txt
				nb_passwords++;
				getchar(); // pause FONCTIONNE PAS POUR RAISON INCONNUE
				break;

			case 2: //menuAddPassword
				printf("\nName : ");
				scanf("%s", taba[nb_passwords].name);
				printf("Login : ");
				scanf("%s", taba[nb_passwords].login);
				printf("Password : ");
				scanf("%s", taba[nb_passwords].password);
				createHash(passwordAttempt, nb_passwords, taba[nb_passwords].hash);
				xorEncryption(taba[nb_passwords].hash, taba[nb_passwords].password, taba[nb_passwords].cipher);
				fprintAccount(taba[nb_passwords]);
				nb_passwords++;
				break;
			
			case 3: // quit
				break;
			
			default:
				break;
		}
	}
	return 0;
}

void erreur_IO (const char *message )
{
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

void hashToString(char *output, const unsigned char *hash)
{
	char buffer[3];
	char hex_hash[HASH_HEX_SIZE] = {0};

	for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
	{
		memset(buffer, 0, sizeof(buffer));
		sprintf(buffer,"%02x", hash[i]);
		strcat(hex_hash, buffer);
	}

	strcpy(output,hex_hash);

	output[HASH_HEX_SIZE] = 0;
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
	printf("\nHash : %s\n", a.hash);
}

/* return 1 if the attempt is the password, otherwise 0 */
int checkPassword(unsigned char *attempt)
{
	tempo(300000000); // to slow brute-force attack
	char *salt = "$klp65q£!bszqHIh7";
	char saltedAttempt[strlen(attempt) + strlen(salt)];
	strcpy(saltedAttempt, attempt);
	strcat(saltedAttempt, salt);
	char *sHashPassword = "3c9096d5407a7f31ee36b283fad1274f044215ace8485ebaf5efc2615abe5eff"; // 0000 + salt
	unsigned char *hashAttempt = SHA256(saltedAttempt, strlen(saltedAttempt), 0);
	char sHashAttempt[HASH_HEX_SIZE];
	hashToString(sHashAttempt, hashAttempt);

	if (strncmp(sHashAttempt, sHashPassword, HASH_HEX_SIZE) == 0)
	{
		return 1;
	}
	/*for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
		printf("%02x", hashAttempt[i]);
	putchar('\n'); */
	printf("Wrong password\n");
	return 0;
}

void password_generator(char p[PASSWORD_LENGTH])
{
	int c; // int in ascii table of the new char
	float p_maj = 0.1; // probability that c will be in MAJ (if it's a letter)
	float a; // 0 <= a <= 1
	srand(time(NULL));   // Initialization, should only be called nonce.

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

void createHash(char *passwordAttempt, int nonce, unsigned char* hash)
{
	int l = strlen(passwordAttempt);
	unsigned char attemptp[l + 1];
	char sNonce[(int) log10(NB_ACCOUNT) + 2];
	sprintf(sNonce, "%d", nonce);
	strcpy(attemptp, passwordAttempt);
	strcat(attemptp, sNonce);
	hashToString(hash, SHA256(attemptp, l+1, 0));
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
/* $Header: https://svn.ita.chalmers.se/repos/security/edu/course/computer_security/trunk/lab/login_linux/login_linux.c 585 2013-01-19 10:31:04Z pk@CHALMERS.SE $ */

/* gcc -std=gnu99 -Wall -g -o mylogin login_linux.c -lcrypt */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <sys/types.h>
#include <crypt.h>

#include "pwent.h" 

#define TRUE 1
#define FALSE 0
#define LENGTH 16

void sighandler2() {}
void sighandler20(){}
//void sighandler3(){}


int main(int argc, char *argv[]) {

	mypwent *passwddata; /* this has to be redefined in step 2 */
	/* see pwent.h */

	char important1[LENGTH] = "**IMPORTANT 1**";

	char user[LENGTH];

	char important2[LENGTH] = "**IMPORTANT 2**";

	//char   *c_pass; //you might want to use this variable later...
	char prompt[] = "password: ";
	char *user_pass;
	char *enpass;
	signal(SIGINT,sighandler2);//CTRL+C,interrupt
	signal(SIGTSTP,sighandler20);//CTRL+z,suspend
	//signal(SIGQUIT,sighandler3);//ctrl+/,quit

	while (TRUE) {
		/* check what important variable contains - do not remove, part of buffer overflow test */
		printf("Value of variable 'important1' before input of login name: %s\n",
				important1);
		printf("Value of variable 'important2' before input of login name: %s\n",
				important2);

		printf("login: ");
		fflush(NULL); /* Flush all  output buffers */
		__fpurge(stdin); /* Purge any data in stdin buffer */
		/*if(gets(user)==NULL)
			exit(0); // overflow attacks.  */
			
		if (fgets(user,LENGTH,stdin) == NULL) /* gets() is vulnerable to buffer */
			exit(0); /*  overflow attacks.  */
		//replace \n with\0
		for(int ptr = 0; ptr < LENGTH; ptr++){
					if (user[ptr] == '\n')
						user[ptr] = '\0';
				}
		/* check to see if important variable is intact after input of login name - do not remove */
		printf("Value of variable 'important 1' after input of login name: %*.*s\n",
				LENGTH - 1, LENGTH - 1, important1);
		printf("Value of variable 'important 2' after input of login name: %*.*s\n",
		 		LENGTH - 1, LENGTH - 1, important2);

		user_pass = getpass(prompt);
		passwddata = mygetpwnam(user);

		if (passwddata != NULL) {
			/* You have to encrypt user_pass for this to work */
			/* Don't forget to include the salt */
			enpass = crypt(user_pass,passwddata->passwd_salt);

         if (!strcmp(enpass, passwddata->passwd)) {

                printf("You're in !\n");
                printf("Number of failed attempts = %d\n", passwddata->pwfailed);
                /*  Reset failed attempts number */
                passwddata->pwfailed = 0;
                /*  Increment password age */
                passwddata->pwage++;
                if (passwddata->pwage > 10)
                    printf("Have logining %d times, please reset your password.\n",   passwddata->pwage);
                mysetpwent(user, passwddata);
				
				if(setuid(passwddata->uid)==-1)
				{
					perror("Set uid falls.\n");
					exit(0);
				}

	/* 			char *pString[] = {"/bin/sh", "-c", "env", 0};
                execve("/bin/sh", &pString[0], (char *[]) {0}); */
				/* transform int to char */
			/* 	char  char_uid[100] = ""; */
				int temp =passwddata->uid;
				printf("Uid is %d \n",temp);
				
				//itoa(temp, char_uid, 10);
				/* snprintf(char_uid,sizeof(char_uid),"%d",temp);
				char * login_information= "Login user is :";
				strcat(login_information,char_uid);
				printf("%s\n",login_information); */
				//if
				if(temp == 0)
				{
					if(execlp("/bin/sh", "Interpter",NULL)==-1)
				{
					perror("execlp fails\n");
					exit(0);
				}
				}
				else{

				printf("Sorry,you have no permission\n");

				}

				/* //Dont add judement
				if(execlp("/bin/sh", "Interpter",NULL)==-1)
				{
					perror("execlp fails\n");
					exit(0);
				} */


				//execl(/bin/sh);
            } 
			else {
                passwddata->pwfailed++;
                mysetpwent(user, passwddata);
                if (passwddata->pwfailed > 5) {
                    printf("Too much login attempts, waiting %d seconds..\n", passwddata->pwfailed - 5);
                    sleep(passwddata->pwfailed);
                }
            }
        }
        printf("Login Incorrect \n");
    }
    return 0;
	//tail -F passdb ，showing changes in teminerte
}

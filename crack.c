#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "md5.h"

const int PASS_LEN = 20;        // Maximum any password will be
const int HASH_LEN = 33;        // Length of MD5 hash strings


// Given a target plaintext word, use it to try to find
// a matching hash in the hashFile.
// Get this function working first!
char * tryWord(char * plaintext, char * hashFilename)
{
    // Hash the plaintext
    char *hashed = md5(plaintext, strlen(plaintext));

    // Open the hash file
    FILE *hashFile = fopen(hashFilename, "r");
    if (hashFile == NULL) 
    {
        fprintf(stderr, "Could not open file %s\n", hashFilename);
        free(hashed);
        return NULL;
    }
    // Loop through the hash file, one line at a time.
    // Attempt to match the hash from the file to the
    // hash of the plaintext.
    // If there is a match, you'll return the hash.
    // If not, return NULL.
    char line[HASH_LEN];
    while (fgets(line, sizeof(line), hashFile) != NULL) 
    {
        line[strcspn(line, "\n")] = 0;
        if (strcmp(hashed, line) == 0) 
        {
            fclose(hashFile);
            char *match = malloc(HASH_LEN);  // Allocate memory for the matched hash
            if (match == NULL) 
            {
                free(hashed);
                return NULL;
            }
        strcpy(match, line);
        free(hashed);
        return match;
        }
    }
    // Before returning, do any needed cleanup:
    //   Close files?
    //   Free memory?

    // Modify this line so it returns the hash
    // that was found, or NULL if not found.
    fclose(hashFile);
    free(hashed);
    return NULL;
    //return "0123456789abcdef0123456789abcdef";
}


int main(int argc, char *argv[])
{

    // These two lines exist for testing. When you have
    // tryWord working, it should display the hash for "hello",
    // which is 5d41402abc4b2a76b9719d911017c592.
    // Then you can remove these two lines and complete the rest
    // of the main function below.
    char *found = tryWord("hello", "hashes00.txt");
    printf("%s %s\n", found, "hello");

    // Open the dictionary file for reading.
    FILE *dictFile = fopen(argv[2], "r");
    if (dictFile == NULL) 
    {
        fprintf(stderr, "Error: Cannot open or read file %s\n", argv[2]);
        exit(1);
    }
    // For each dictionary word, pass it to tryWord, which
    // will attempt to match it against the hashes in the hash_file.
    char word[PASS_LEN];
    int count = 0;
    
    // If we got a match, display the hash and the word. For example:
    //   5d41402abc4b2a76b9719d911017c592 hello
    while (fgets(word, sizeof(word), dictFile) != NULL) 
    {
        word[strcspn(word, "\n")] = 0;
        char *found = tryWord(word, argv[1]);

        if (found != NULL) 
        {
            printf("%s %s\n", found, word);
            count++;
            free(found);
        }

    }
    // Close the dictionary file.
    fclose(dictFile);
    // Display the number of hashes that were cracked.
    printf("%d hashes cracked!\n", count);
    // Free up any malloc'd memory?
    return 0;
}


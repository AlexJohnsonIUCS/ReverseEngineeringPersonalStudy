#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


int healthPrint(){
    int health = 100;
    while(health > 0){
        printf("Your health is: %d\n", health);
        health--;
        sleep(10);
    }
    
    return health;
}

int main() {
    healthPrint();
    return 0;
}

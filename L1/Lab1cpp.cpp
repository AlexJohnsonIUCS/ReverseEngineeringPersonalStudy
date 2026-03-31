#include <iostream>

int healthPrint(){
    int health = 100;
    while(health > 0){
        std::cout << "Your health is: " << health << std::endl;
        health--;
    }
    return 0;
}

int main(){
    healthPrint();
    return 0;
}

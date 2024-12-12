# installs the module random for generating random numbers
# installs the module pickle for serialization and deserialization of objects
import random
import pickle

# this creates a class for player with __init__ method initializes a player with name and score
# all players start with a score of 0, and a name which is to be declared later
class Player:
    def __init__(self, name):
        self.name = name
        self.score = 0

# similarly this creates a class for card to initialize suit and rank
# The usual __str__ method is replaced to provide a human readable string of a card
# returning chosen card as long as card is not a joker, otherwise joker is chosen
class Card:
    def __init__(self, suit, rank):
        self.suit = suit
        self.rank = rank

    def __str__(self):
        return f"{self.rank} of {self.suit}" if self.rank != "Joker" else "Joker"

# the class for the game itself, using the __init__ method to intialize two players,
# a round number, an empty deck and a list for all ranks and suits
class WarGame:
    def __init__(self):
        self.player1 = Player("")
        self.player2 = Player("")
        self.round_number = 1
        self.deck = []
        self.ranks = []
        self.suits = []

    # method for the welcome message when entering the game, explicitly stating the rules
    def rules(self):
        print("Welcome to Python War Card Game!")
        print("Rules:")
        print("- Draw higher-ranked cards to win rounds and earn points.")
        print("- If a Joker is drawn, gain a point in the first round, steal a point from the opponent in subsequent rounds.")
        print("- If two Aces are drawn simultaneously, both players scores will be reset.")
        print("- The player with the highest score at the end wins!")

    # method for getting the users name as a valid string input
    # should it not be a string of letters the program will request the user to type a valid input
    # requests will continue until a valid input is entered, checked by the .isalpha method
    # .isalpha checks if the input contains only letters
    def name(self):
        while True:
            name = input("Enter your name: ").capitalize()
            if name.isalpha():
                return name
            else:
                print("Invalid input. Please enter a valid name with only letters.")

    # method which checks for valid input, this time in the form of an integer
    # this block of code requests a number of rounds from the user
    # try and except is also utilised here to handle any value errors
    def round_count(self):
        while True:
            try:
                rounds = int(input("How many rounds would you like to play? "))
                if rounds > 0:
                    return rounds
                else:
                    print("Please enter a positive integer greater than 0.")
            except ValueError:
                print("Invalid input. Please enter a valid integer.")

    # method for creating the deck, making use of 2D arrays to give each rank a suit
    def make_deck(self):
        self.suits = ['Hearts', 'Diamonds', 'Clubs', 'Spades']
        self.ranks = ['2', '3', '4', '5', '6', '7', '8', '9', '10', 'Jack', 'Queen', 'King', 'Ace', 'Joker']
        self.deck = [Card(suit, rank) for suit in self.suits for rank in self.ranks]
        return self.ranks

    # method for simulating removing a card from the deck at random if the deck is not empty
    # if the deck is empty it calls upon the initialize_deck method to create a new deck
    def draw_card(self):
        if not self.deck:
            self.ranks = self.make_deck()

        # once a random card is chosen, it will be removed from the deck using method
        # .remove with parameter drawn card
        drawn_card = random.choice(self.deck)
        self.deck.remove(drawn_card)
        return drawn_card

    # method to save game utilizing the pickle module (dump) installed at the beginning
    def save_game(self):
        with open('war_game_save.pkl', 'wb') as file:
            pickle.dump(self, file)
        print("Game saved successfully.")

    # method to load the game from memory utilizing the pickle module (load)
    # try and except clauses utilised to check for file errors
    def load_game(self):
        try:
            with open('war_game_save.pkl', 'rb') as file:
                saved_game = pickle.load(file)
            return saved_game
        except FileNotFoundError:
            print("No saved game found.")
            return None

    # method to play a round of the game, players draw a card each utilizing the draw_card method
    def play_round(self):
        print(f"\n--- Round {self.round_number} ---")

        card1 = self.draw_card()
        card2 = self.draw_card()

        print(f"{self.player1.name} draws: {card1}")
        print(f"{self.player2.name} draws: {card2}")

        # conditions for who wins are checked here using the if, elif and else statements
        # if round number is 1 then a point is awarded for a joker rather than stolen from another player
        # the condition being it is the first round and a joker was drawn
        if card1.rank == 'Joker' and self.round_number == 1:
            print(f"{self.player1.name} gains a point in the first round!")
            self.player1.score += 1
        elif card2.rank == 'Joker' and self.round_number == 1:
            print(f"{self.player2.name} gains a point in the first round!")
            self.player2.score += 1
        elif card1.rank == card2.rank:
            print("It's a tie! Tiebreaker round:")

            # tiebreak condtions are placed in a loop for when there is a requirement for multiple tiebreaks
            while True:
                tiebreaker_card1 = self.draw_card()
                tiebreaker_card2 = self.draw_card()

                print(f"{self.player1.name} draws for tiebreaker: {tiebreaker_card1}")
                print(f"{self.player2.name} draws for tiebreaker: {tiebreaker_card2}")

                if self.ranks.index(tiebreaker_card1.rank) > self.ranks.index(tiebreaker_card2.rank):
                    print(f"{self.player1.name} wins the tiebreaker!")
                    self.player1.score += 1
                    break
                elif self.ranks.index(tiebreaker_card1.rank) < self.ranks.index(tiebreaker_card2.rank):
                    print(f"{self.player2.name} wins the tiebreaker!")
                    self.player2.score += 1
                    break
                else:
                    print("It's a tie again! Another tiebreaker round:")

        # joker and double ace conditions are specified here
        elif card1.rank == 'Joker':
            print(f"{self.player1.name} steals a point from {self.player2.name}!")
            self.player2.score -= 1
        elif card2.rank == 'Joker':
            print(f"{self.player2.name} steals a point from {self.player1.name}!")
            self.player1.score -= 1
        elif card1.rank == 'Ace' and card2.rank == 'Ace':
            print("Double Aces! Scores reset for both players.")
            self.player1.score = 0
            self.player2.score = 0
        elif self.ranks.index(card1.rank) > self.ranks.index(card2.rank):
            print(f"{self.player1.name} wins the round!")
            self.player1.score += 1
        else:
            print(f"{self.player2.name} wins the round!")
            self.player2.score += 1

        # scores are displayed at the end of each round as well as the option to save game
        print(f"Scores: {self.player1.name}: {self.player1.score}, {self.player2.name}: {self.player2.score}")

        # method will check for valid user input, accepting 'y' or 'n' only
        save_choice = input("Do you want to save the game and exit? (y/n): ").lower()
        while save_choice not in ['y', 'n']:
            print("Invalid input. Please enter 'y' or 'n'.")
            save_choice = input("Do you want to save the game and exit? (y/n): ").lower()

        # if user chooses y, game will save and exit otherwise game will prompt user to press enter to continue
        if save_choice == 'y':
            self.save_game()
            exit()

        input("Press Enter to continue...")

    # method to start game utilizing methods created before
    def start_game(self):
        self.rules()

        self.player1.name = self.name()
        self.player2.name = "Computer"

        # whilst the round number limit specified by user is not reached the game will continue
        rounds_to_play = self.round_count()

        # adding 1 to the round counter each round
        while self.round_number <= rounds_to_play:
            self.play_round()
            self.round_number += 1

        # once round limit is reached the winner is determined by the greater than or less than operand
        if self.player1.score > self.player2.score:
            print(f"\n{self.player1.name} wins the game with a score of {self.player1.score}!")
        elif self.player1.score < self.player2.score:
            print(f"\n{self.player2.name} wins the game with a score of {self.player2.score}!")
        else:
            print("\nIt's a tie! The game is a draw.")

# how to start the game, calling previously defined methods amd attributing war_game to subclass WarGame
war_game = WarGame()
war_game.start_game()

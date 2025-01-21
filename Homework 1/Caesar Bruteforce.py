def caesar_decrypt(ciphertext, shift):
  result = ''
  for char in ciphertext:
    # Checks if the current character is an alphabetical letter, skips the shifting if it is not
    if char.isalpha():
      # Identifies if a letter is upper or lower case to identify the starting point for the shift
      start = ord('a') if char.islower() else ord('A')
      #shifts the character accordingly
      shifted_char = chr((ord(char) - start - shift) % 26 + start)
    else:
      shifted_char = char
    result += shifted_char
  return result

ciphertext = input("Enter ciphertext here: ")
print("")

for shift in range(1, 26):
  decrypted_text = caesar_decrypt(ciphertext, shift)
  print("Shift",shift, ": ",decrypted_text)
# Encounters

# Can upload images to avatar in profile
## Observations
- Can upload image to avatar but it has to be a 'valid' image. 
- Could get bypass if we included the magic bits from a PNG so it was doing image validation but not mime or extension type. 
- Added PHP after the magic bits and changed the extension to php to get execution. 
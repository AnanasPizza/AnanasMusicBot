function isNumberFromOneToTen(number) {
    try {
      let intNum = parseInt(number);
      if (intNum >= 1 && intNum <= 10) {
        return true;
      }
    } catch (error) {
      return false;
    }
    return false;
  }
  
function convertMillisecondsToMinuteSeconds(milliseconds) {
  // Calculate minutes and seconds
  const minutes = Math.floor(milliseconds / 60000);
  const seconds = ((milliseconds % 60000) / 1000).toFixed(0);
  
  // Ensure that both minutes and seconds are two characters long
  const formattedMinutes = minutes.toString().padStart(2, '0');
  const formattedSeconds = seconds.toString().padStart(2, '0');

  return `${formattedMinutes}:${formattedSeconds}`;
}

export {isNumberFromOneToTen, convertMillisecondsToMinuteSeconds}
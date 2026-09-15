// Each automated operation temporarily borrows control, then returns it to the visitor.
export async function withAutomation(setStream, operation) {
  try {
    await setStream('ENABLED');
    return await operation();
  } finally {
    await setStream('DISABLED');
  }
}

// Sets up a global 'include' function so we can require files
// relative to the project root from anywhere in the codebase.
// Usage: const {database} = include('databaseConnection');
global.include = (module) => {
    return require(__dirname + '/' + module);
};

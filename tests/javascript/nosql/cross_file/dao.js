function search(threshold) {
  return {$where: `this.stocks > '${threshold}'`};
}

module.exports = {search};

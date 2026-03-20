// Force all TOC subsections to stay expanded
document.addEventListener('DOMContentLoaded', function() {
  // Wait for TOC to load
  setTimeout(function() {
    // Find all TOC list items
    const tocList = document.querySelector('#toc-wrapper ul');
    if (tocList) {
      // Force show all nested lists
      const nestedLists = tocList.querySelectorAll('ul');
      nestedLists.forEach(ul => {
        ul.style.display = 'block';
      });
      
      // Remove collapse/expand behavior
      const tocLinks = tocList.querySelectorAll('a');
      tocLinks.forEach(link => {
        link.addEventListener('click', function(e) {
          const nextUl = this.nextElementSibling;
          if (nextUl && nextUl.tagName === 'UL') {
            nextUl.style.display = 'block';
          }
        });
      });
    }
  }, 100);
});
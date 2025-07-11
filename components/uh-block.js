'use strict';
polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  // Session Paging Variables
  filterValue: '',
  currentPage: 1,
  pageSize: 5,
  pagingData: Ember.computed.alias('details.urls'),
  filteredPagingData: Ember.computed('pagingData.length', 'filterValue', function () {
    // reset to page 1 when filter changes
    this.set('currentPage', 1);

    let filterValue = this.get('filterValue');

    if (filterValue) {
      filterValue = filterValue.toLowerCase().trim();
      if (filterValue.length > 0) {
        return this.get('pagingData').filter((entry) => {
          return entry.url.toLowerCase().includes(filterValue);
        });
      }
    }

    return this.get('pagingData');
  }),
  isPrevButtonsDisabled: Ember.computed('currentPage', function () {
    return this.get('currentPage') === 1;
  }),
  isNextButtonDisabled: Ember.computed('filteredPagingData.length', 'pageSize', 'currentPage', function () {
    const totalResults = this.get('filteredPagingData.length');
    const totalPages = Math.ceil(totalResults / this.get('pageSize'));
    return this.get('currentPage') === totalPages;
  }),
  pagingStartItem: Ember.computed('currentPage', 'pageSize', function () {
    return (this.get('currentPage') - 1) * this.get('pageSize') + 1;
  }),
  pagingEndItem: Ember.computed('pagingStartItem', function () {
    return this.get('pagingStartItem') - 1 + this.get('pageSize');
  }),
  pagedPagingData: Ember.computed('filteredPagingData.length', 'pageSize', 'currentPage', function () {
    if (!this.get('filteredPagingData')) {
      return [];
    }
    const startIndex = (this.get('currentPage') - 1) * this.get('pageSize');
    const endIndex = startIndex + this.get('pageSize');

    return this.get('filteredPagingData').slice(startIndex, endIndex);
  }),
  // End of Paging Variables
  actions: {
    // Start Paging Actions
    prevPage() {
      let currentPage = this.get('currentPage');

      if (currentPage > 1) {
        this.set('currentPage', currentPage - 1);
      }
    },
    nextPage() {
      const totalResults = this.get('filteredPagingData.length');
      const totalPages = Math.ceil(totalResults / this.get('pageSize'));
      let currentPage = this.get('currentPage');
      if (currentPage < totalPages) {
        this.set('currentPage', currentPage + 1);
      }
    },
    firstPage() {
      this.set('currentPage', 1);
    },
    lastPage() {
      const totalResults = this.get('filteredPagingData.length');
      const totalPages = Math.ceil(totalResults / this.get('pageSize'));
      this.set('currentPage', totalPages);
    },
    // End Paging Actions
    retryLookup: function () {
      this.set('running', true);
      this.set('errorMessage', '');
      const payload = {
        action: 'RETRY_LOOKUP',
        entity: this.get('block.entity')
      };
      this.sendIntegrationMessage(payload)
        .then((result) => {
          if (result.data.summary) this.set('summary', result.summary);
          this.set('block.data', result.data);
        })
        .catch((err) => {
          this.set('details.errorMessage', JSON.stringify(err, null, 4));
        })
        .finally(() => {
          this.set('running', false);
        });
    }
  }
});

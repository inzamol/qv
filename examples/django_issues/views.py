from django.http import JsonResponse

from .models import Author, Book


def list_authors_and_books(request):
    authors = Author.objects.all()
    data = []
    # DJG-004: N+1 query execution inside loop without select_related / prefetch_related
    for author in authors:
        books = Book.objects.filter(author=author)
        data.append(
            {
                "author": author.name,
                "book_count": len(books),
            }
        )
    return JsonResponse({"data": data})

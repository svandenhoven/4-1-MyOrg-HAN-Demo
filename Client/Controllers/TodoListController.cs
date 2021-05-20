using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Identity.Web;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using TodoListClient.Services;
using TodoListService.Models;

namespace TodoListClient.Controllers
{
    public class TodoListController : Controller
    {
        private ITodoListService _todoListService;

        public TodoListController(ITodoListService todoListService)
        {
            _todoListService = todoListService;
        }

        // GET: TodoList
        public async Task<ActionResult> Index()
        {
            if (!(User.IsInRole("Writer") || User.IsInRole("Reader") || User.IsInRole("Admin")))
            {
                return Unauthorized();
            }

            return View(await _todoListService.GetAsync());
        }

        // GET: TodoList/Details/5
        [Authorize(Policy = "ReadersPolicy")]
        public async Task<ActionResult> Details(int id)
        {
            return View(await _todoListService.GetAsync(id));
        }

        // GET: TodoList/Create
        [Authorize(Policy = "WritersPolicy")]
        public ActionResult Create()
        {
            Todo todo = new Todo() { Owner = HttpContext.User.Identity.Name };
            return View(todo);
        }

        // POST: TodoList/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Policy = "WritersPolicy")]
        public async Task<ActionResult> Create([Bind("Title,Owner")] Todo todo)
        {
            await _todoListService.AddAsync(todo);
            return RedirectToAction("Index");
        }

        // GET: TodoList/Edit/5
        [Authorize(Policy = "WritersPolicy")]
        public async Task<ActionResult> Edit(int id)
        {
            Todo todo = await this._todoListService.GetAsync(id);

            if (todo == null)
            {
                return NotFound();
            }

            return View(todo);
        }

        // POST: TodoList/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Policy = "WritersPolicy")]
        public async Task<ActionResult> Edit(int id, [Bind("Id,Title,Owner")] Todo todo)
        {
            var _tenantId = ((ClaimsIdentity)User.Identity).Claims.Where(c => c.Type == "http://schemas.microsoft.com/identity/claims/tenantid").FirstOrDefault().Value;
            todo.TenantId = _tenantId;

            await _todoListService.EditAsync(todo);
            return RedirectToAction("Index");
        }

        // GET: TodoList/Delete/5
        [Authorize(Policy = "WritersPolicy")]
        public async Task<ActionResult> Delete(int id)
        {
            Todo todo = await this._todoListService.GetAsync(id);

            if (todo == null)
            {
                return NotFound();
            }

            return View(todo);
        }

        // POST: TodoList/Delete/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Policy = "WritersPolicy")]
        public async Task<ActionResult> Delete(int id, [Bind("Id,Title,Owner")] Todo todo)
        {
            await _todoListService.DeleteAsync(id);
            return RedirectToAction("Index");
        }
    }
}
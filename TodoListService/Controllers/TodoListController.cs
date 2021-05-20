/*
 The MIT License (MIT)

Copyright (c) 2018 Microsoft Corporation

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
 */

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Identity.Web.Resource;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using TodoListService.Models;
using Microsoft.Identity.Web;
using System;
using System.Diagnostics;

namespace TodoListService.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    public class TodoListController : Controller
    {
        // In-memory TodoList
        private static readonly Dictionary<int, Todo> TodoStore = new Dictionary<int, Todo>();

        private readonly IHttpContextAccessor _contextAccessor;
        private readonly string _tenantId;
        private string[] _scopes;

        public TodoListController(IHttpContextAccessor contextAccessor)
        {
            this._contextAccessor = contextAccessor;

            _tenantId = ((ClaimsIdentity)this._contextAccessor.HttpContext.User.Identity).Claims.Where(c => c.Type == "http://schemas.microsoft.com/identity/claims/tenantid").FirstOrDefault().Value;
            _scopes = ((ClaimsIdentity)this._contextAccessor.HttpContext.User.Identity).Claims.Where(c => c.Type == "http://schemas.microsoft.com/identity/claims/scope").FirstOrDefault().Value.Split(" ");

            // Pre-populate with sample data
            if (TodoStore.Count == 0)
            {
                TodoStore.Add(1, new Todo() { Id = 1, Owner = $"{this._contextAccessor.HttpContext.User.Identity.Name}", Title = "Pick up groceries", TenantId = _tenantId });
                TodoStore.Add(2, new Todo() { Id = 2, Owner = $"{this._contextAccessor.HttpContext.User.Identity.Name}", Title = "Finish invoice report", TenantId = _tenantId });
            }
        }

        // GET: api/values
        [HttpGet]
        [Authorize(Policy = "ReadersPolicy")]
        public ActionResult<IEnumerable<Todo>> Get()
        {
            if(!(User.IsInRole("Writer") || User.IsInRole("Reader") || User.IsInRole("Admin")) || !_scopes.Contains("ToDo.Read"))
            {
                return Unauthorized();
            }

            if (User.IsInRole("Admin"))
            {
                return Ok(TodoStore.Values.Where(x => x.TenantId == _tenantId));
            }
            else
            {
                string owner = User.Identity.Name;
                return Ok(TodoStore.Values.Where(x => x.Owner == owner && x.TenantId == _tenantId));
            }
        }

        // GET: api/values
        [HttpGet("{id}", Name = "Get")]
        [Authorize(Policy = "WritersPolicy")]
        public ActionResult<Todo> Get(int id)
        {
            try
            {
                HttpContext.VerifyUserHasAnyAcceptedScope(new[] { "ToDo.Read" });
                return Ok(TodoStore.Values.FirstOrDefault(t => t.Id == id && t.TenantId == _tenantId));
            }
            catch(Exception ex)
            {
                Debug.WriteLine(ex.Message);
                return Unauthorized();
            }
        }

        [HttpDelete("{id}")]
        [Authorize(Policy = "WritersPolicy")]
        public void Delete(int id)
        {
            TodoStore.Remove(id);
        }

        // POST api/values
        [HttpPost]
        [Authorize(Policy = "WritersPolicy")]
        public IActionResult Post([FromBody] Todo todo)
        {
            HttpContext.VerifyUserHasAnyAcceptedScope(new[] { "ToDo.Write" });
            var owner = HttpContext.User.Identity.Name;
            if(User.IsInRole("Admin"))
            {
                owner = todo.Owner;
            }
            int id = TodoStore.Values.OrderByDescending(x => x.Id).FirstOrDefault().Id + 1;
            Todo todonew = new Todo() { Id = id, Owner = owner, Title = todo.Title, TenantId = _tenantId };
            TodoStore.Add(id, todonew);

            return Ok(todo);
        }

        // PATCH api/values
        [HttpPatch("{id}")]
        [Authorize(Policy = "WritersPolicy")]
        public IActionResult Patch(int id, [FromBody] Todo todo)
        {
            HttpContext.VerifyUserHasAnyAcceptedScope(new[] { "ToDo.Write" });
            if (id != todo.Id)
            {
                return NotFound();
            }

            if (TodoStore.Values.FirstOrDefault(x => x.Id == id && x.TenantId == _tenantId) == null)
            {
                return NotFound();
            }

            TodoStore.Remove(id);
            todo.TenantId = _tenantId;
            TodoStore.Add(id, todo);

            return Ok(todo);
        }
    }
}